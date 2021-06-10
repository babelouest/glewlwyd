/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 *
 * Declarations for common constants and prototypes used in Glewlwyd main program and modules
 *
 * Copyright 2016-2021 Nicolas Mora <mail@babelouest.org>
 *
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#ifndef __GLEWLWYD_COMMON_H_
#define __GLEWLWYD_COMMON_H_

#include <jansson.h>

#include <ulfius.h>
#include <yder.h>
#include <hoel.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "static_compressed_inmemory_website_callback.h"
#include "http_compression_callback.h"

/**
 * Result values used in the application
 */
#define G_OK                 0
#define G_ERROR              1
#define G_ERROR_UNAUTHORIZED 2
#define G_ERROR_PARAM        3
#define G_ERROR_DB           4
#define G_ERROR_MEMORY       5
#define G_ERROR_NOT_FOUND    6

/**
 * Callback priority
 */
#define GLEWLWYD_CALLBACK_PRIORITY_ZERO            0
#define GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION  1
#define GLEWLWYD_CALLBACK_PRIORITY_PRE_APPLICATION 2
#define GLEWLWYD_CALLBACK_PRIORITY_APPLICATION     3
#define GLEWLWYD_CALLBACK_PRIORITY_COMPRESSION     4
#define GLEWLWYD_CALLBACK_PRIORITY_PLUGIN          5
#define GLEWLWYD_CALLBACK_PRIORITY_FILE            100
#define GLEWLWYD_CALLBACK_PRIORITY_POST_FILE       101

/**
 * Modes available when adding or modifying a user
 */
#define GLEWLWYD_IS_VALID_MODE_ADD            0
#define GLEWLWYD_IS_VALID_MODE_UPDATE         1
#define GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE 2

/**
 * Modes available of the availability of a scheme for a user
 */
#define GLEWLWYD_IS_NOT_AVAILABLE 0
#define GLEWLWYD_IS_AVAILABLE     1
#define GLEWLWYD_IS_REGISTERED    2

/**
 * Modes available to delete a profile
 */
#define GLEWLWYD_PROFILE_DELETE_UNAUTHORIZED    0x0000
#define GLEWLWYD_PROFILE_DELETE_AUTHORIZED      0x0001
#define GLEWLWYD_PROFILE_DELETE_DISABLE_PROFILE 0x0010

#define GLEWLWYD_DEFAULT_LIMIT_SIZE 100

#define GLEWLWYD_DEFAULT_SALT_LENGTH 16

#define G_PBKDF2_ITERATOR_DEFAULT 150000

#define SWITCH_DB_TYPE(T, M, S, P) \
        ((T)==HOEL_DB_TYPE_MARIADB?\
           (M):\
         (T)==HOEL_DB_TYPE_SQLITE?\
           (S):\
           (P)\
        )

#define MIN(A, B) ((A)>(B)?(B):(A))
#define MAX(A, B) ((A)>(B)?(A):(B))

/** Macro to avoid compiler warning when some parameters are unused and that's ok **/
#define UNUSED(x) (void)(x)

/**
 * Digest format available
 */
typedef enum {
  digest_SHA1,
  digest_SSHA1,
  digest_SHA224,
  digest_SSHA224,
  digest_SHA256,
  digest_SSHA256,
  digest_SHA384,
  digest_SSHA384,
  digest_SHA512,
  digest_SSHA512,
  digest_MD5,
  digest_SMD5,
  digest_PBKDF2_SHA256,
  digest_CRYPT,
  digest_CRYPT_MD5,
  digest_CRYPT_SHA256,
  digest_CRYPT_SHA512,
  digest_PLAIN
} digest_algorithm;

struct config_module;

/**
 * Structure used to store a user module
 */
struct _user_module {
  void      * file_handle;
  char      * name;
  char      * display_name;
  char      * description;
  double      api_version;
  json_t * (* user_module_load)(struct config_module * config);
  int      (* user_module_unload)(struct config_module * config);
  json_t * (* user_module_init)(struct config_module * config, int readonly, int multiple_passwords, json_t * j_parameters, void ** cls);
  int      (* user_module_close)(struct config_module * config, void * cls);
  size_t   (* user_module_count_total)(struct config_module * config, const char * pattern, void * cls);
  json_t * (* user_module_get_list)(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls);
  json_t * (* user_module_get)(struct config_module * config, const char * username, void * cls);
  json_t * (* user_module_get_profile)(struct config_module * config, const char * username, void * cls);
  json_t * (* user_module_is_valid)(struct config_module * config, const char * username, json_t * j_user, int mode, void * cls);
  int      (* user_module_add)(struct config_module * config, json_t * j_user, void * cls);
  int      (* user_module_update)(struct config_module * config, const char * username, json_t * j_user, void * cls);
  int      (* user_module_update_profile)(struct config_module * config, const char * username, json_t * j_user, void * cls);
  int      (* user_module_delete)(struct config_module * config, const char * username, void * cls);
  int      (* user_module_check_password)(struct config_module * config, const char * username, const char * password, void * cls);
  int      (* user_module_update_password)(struct config_module * config, const char * username, const char ** new_passwords, size_t new_passwords_len, void * cls);
};

/**
 * Structure used to store a user middleware module
 */
struct _user_middleware_module {
  void      * file_handle;
  char      * name;
  char      * display_name;
  char      * description;
  double      api_version;
  json_t * (* user_middleware_module_load)(struct config_module * config);
  int      (* user_middleware_module_unload)(struct config_module * config);
  json_t * (* user_middleware_module_init)(struct config_module * config, json_t * j_parameters, void ** cls);
  int      (* user_middleware_module_close)(struct config_module * config, void * cls);
  int      (* user_middleware_module_get_list)(struct config_module * config, json_t * j_user_list, void * cls);
  int      (* user_middleware_module_get)(struct config_module * config, const char * username, json_t * j_user, void * cls);
  int      (* user_middleware_module_get_profile)(struct config_module * config, const char * username, json_t * j_user, void * cls);
  int      (* user_middleware_module_update)(struct config_module * config, const char * username, json_t * j_user, void * cls);
  int      (* user_middleware_module_delete)(struct config_module * config, const char * username, json_t * j_user, void * cls);
};

/**
 * Structure used to store a user module instance
 */
struct _user_module_instance {
  char                * name;
  struct _user_module * module;
  void                * cls;
  short int             enabled;
  short int             readonly;
  short int             multiple_passwords;
};

/**
 * Structure used to store a user middleware module instance
 */
struct _user_middleware_module_instance {
  char                           * name;
  struct _user_middleware_module * module;
  void                           * cls;
  short int                        enabled;
};

/**
 * Structure used to store a client module
 */
struct _client_module {
  void     * file_handle;
  char     * name;
  char     * display_name;
  char     * description;
  double     api_version;
  json_t * (* client_module_load)(struct config_module * config);
  int      (* client_module_unload)(struct config_module * config);
  json_t * (* client_module_init)(struct config_module * config, int readonly, json_t * j_parameters, void ** cls);
  int      (* client_module_close)(struct config_module * config, void * cls);
  size_t   (* client_module_count_total)(struct config_module * config, const char * pattern, void * cls);
  json_t * (* client_module_get_list)(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls);
  json_t * (* client_module_get)(struct config_module * config, const char * client_id, void * cls);
  json_t * (* client_module_is_valid)(struct config_module * config, const char * client_id, json_t * j_client, int mode, void * cls);
  int      (* client_module_add)(struct config_module * config, json_t * j_client, void * cls);
  int      (* client_module_update)(struct config_module * config, const char * client_id, json_t * j_client, void * cls);
  int      (* client_module_delete)(struct config_module * config, const char * client_id, void * cls);
  int      (* client_module_check_password)(struct config_module * config, const char * client_id, const char * password, void * cls);
};

/**
 * Structure used to store a client module instance
 */
struct _client_module_instance {
  char                  * name;
  struct _client_module * module;
  void                  * cls;
  short int               enabled;
  short int               readonly;
};

/**
 * Structure used to store a user auth schem module
 */
struct _user_auth_scheme_module {
  void       * file_handle;
  char       * name;
  char       * display_name;
  char       * description;
  double       api_version;
  json_t  * (* user_auth_scheme_module_load)(struct config_module * config);
  int       (* user_auth_scheme_module_unload)(struct config_module * config);
  json_t *  (* user_auth_scheme_module_init)(struct config_module * config, json_t * j_parameters, const char * mod_name, void ** cls);
  int       (* user_auth_scheme_module_close)(struct config_module * config, void * cls);
  int       (* user_auth_scheme_module_can_use)(struct config_module * config, const char * username, void * cls);
  json_t  * (* user_auth_scheme_module_register)(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls);
  json_t  * (* user_auth_scheme_module_register_get)(struct config_module * config, const struct _u_request * http_request, const char * username, void * cls);
  int       (* user_auth_scheme_module_deregister)(struct config_module * config, const char * username, void * cls);
  json_t  * (* user_auth_scheme_module_trigger)(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_trigger, void * cls);
  int       (* user_auth_scheme_module_validate)(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls);
  json_t *  (* user_auth_scheme_module_identify)(struct config_module * config, const struct _u_request * http_request, json_t * j_scheme_data, void * cls);
};

/**
 * Structure used to store a user auth schem module instance
 */
struct _user_auth_scheme_module_instance {
  char                            * name;
  struct _user_auth_scheme_module * module;
  json_int_t                        guasmi_id;
  json_int_t                        guasmi_expiration;
  json_int_t                        guasmi_max_use;
  short int                         guasmi_allow_user_register;
  short int                         guasmi_forbid_user_profile;
  short int                         guasmi_forbid_user_reset_credential;
  void                            * cls;
  short int                         enabled;
};

struct config_plugin;

/**
 * Structure used to store a plugin module
 */
struct _plugin_module {
  void      * file_handle;
  char      * name;
  char      * display_name;
  char      * description;
  double      api_version;
  json_t * (* plugin_module_load)(struct config_plugin * config);
  int      (* plugin_module_unload)(struct config_plugin * config);
  json_t * (* plugin_module_init)(struct config_plugin * config, const char * name, json_t * j_parameters, void ** cls);
  int      (* plugin_module_close)(struct config_plugin * config, const char * name, void * cls);
};

/**
 * Structure used to store a plugin module instance
 */
struct _plugin_module_instance {
  char                  * name;
  struct _plugin_module * module;
  void                  * cls;
  short int               enabled;
};

#define GLWD_METRICS_AUTH_USER_VALID          "glewlwyd_auth_user_valid"
#define GLWD_METRICS_AUTH_USER_VALID_SCHEME   "glewlwyd_auth_user_valid_scheme"
#define GLWD_METRICS_AUTH_USER_INVALID        "glewlwyd_auth_user_invalid"
#define GLWD_METRICS_AUTH_USER_INVALID_SCHEME "glewlwyd_auth_user_invalid_scheme"
#define GLWD_METRICS_DATABSE_ERROR            "glewlwyd_database_error"

/**
 * Structure used to store a prometheus metrics
 */
struct _glwd_metrics_data {
  char * label;
  size_t counter;
};

struct _glwd_metric {
  char                      * name;
  char                      * help;
  struct _glwd_metrics_data * data;
  size_t                      data_size;
};

/**
 * Structure used to store the global application config
 */
struct config_elements {
  char *                                         config_file;
  unsigned int                                   port;
  char *                                         bind_address;
  char *                                         bind_address_metrics;
  char *                                         external_url;
  char *                                         api_prefix;
  char *                                         cookie_domain;
  unsigned int                                   cookie_secure;
  unsigned short                                 log_mode_args;
  unsigned short                                 log_level_args;
  unsigned long                                  log_mode;
  unsigned long                                  log_level;
  char *                                         log_file;
  struct _u_compressed_inmemory_website_config * static_file_config;
  char *                                         admin_scope;
  char *                                         profile_scope;
  char *                                         allow_origin;
  unsigned int                                   use_secure_connection;
  char *                                         secure_connection_key_file;
  char *                                         secure_connection_pem_file;
  char *                                         secure_connection_ca_file;
  struct _h_connection *                         conn;
  struct _u_instance *                           instance;
  unsigned int                                   instance_initialized;
  struct _u_instance *                           instance_metrics;
  unsigned int                                   instance_metrics_initialized;
  char *                                         session_key;
  unsigned int                                   session_expiration;
  unsigned int                                   salt_length;
  digest_algorithm                               hash_algorithm;
  char *                                         login_url;
  unsigned int                                   delete_profile;
  char *                                         user_module_path;
  struct _pointer_list *                         user_module_list;
  struct _pointer_list *                         user_module_instance_list;
  char *                                         user_middleware_module_path;
  struct _pointer_list *                         user_middleware_module_list;
  struct _pointer_list *                         user_middleware_module_instance_list;
  char *                                         client_module_path;
  struct _pointer_list *                         client_module_list;
  struct _pointer_list *                         client_module_instance_list;
  char *                                         user_auth_scheme_module_path;
  struct _pointer_list *                         user_auth_scheme_module_list;
  struct _pointer_list *                         user_auth_scheme_module_instance_list;
  char *                                         plugin_module_path;
  struct _pointer_list *                         plugin_module_list;
  struct _pointer_list *                         plugin_module_instance_list;
  struct config_plugin *                         config_p;
  struct config_module *                         config_m;
  unsigned short                                 metrics_endpoint;
  unsigned int                                   metrics_endpoint_port;
  unsigned short                                 metrics_endpoint_admin_session;
  pthread_mutex_t                                metrics_lock;
  struct _pointer_list                           metrics_list;
};

/**
 * Structure given to all plugin functions that will contain configuration on the
 * application host, and pointer to functions of the application host
 */
struct config_plugin {
  struct config_elements * glewlwyd_config;
  int      (* glewlwyd_callback_add_plugin_endpoint)(struct config_plugin * config, const char * method, const char * name, const char * url, unsigned int priority, int (* callback)(const struct _u_request * request, struct _u_response * response, void * user_data), void * user_data);
  int      (* glewlwyd_callback_remove_plugin_endpoint)(struct config_plugin * config, const char * method, const char * name, const char * url);

  // Session callback functions
  json_t * (* glewlwyd_callback_check_session_valid)(struct config_plugin * config, const struct _u_request * request, const char * scope_list);
  json_t * (* glewlwyd_callback_check_user_valid)(struct config_plugin * config, const char * username, const char * password, const char * scope_list);
  json_t * (* glewlwyd_callback_check_client_valid)(struct config_plugin * config, const char * client_id, const char * password);
  int      (* glewlwyd_callback_trigger_session_used)(struct config_plugin * config, const struct _u_request * request, const char * scope_list);
  time_t   (* glewlwyd_callback_get_session_age)(struct config_plugin * config, const struct _u_request * request, const char * scope_list);

  // Client callback functions
  json_t * (* glewlwyd_callback_get_client_granted_scopes)(struct config_plugin * config, const char * client_id, const char * username, const char * scope_list);

  // User CRUD
  json_t * (* glewlwyd_plugin_callback_get_user_list)(struct config_plugin * config, const char * pattern, size_t offset, size_t limit);
  json_t * (* glewlwyd_plugin_callback_get_user)(struct config_plugin * config, const char * username);
  json_t * (* glewlwyd_plugin_callback_get_user_profile)(struct config_plugin * config, const char * username);
  json_t * (* glewlwyd_plugin_callback_is_user_valid)(struct config_plugin * config, const char * username, json_t * j_user, int add);
  int      (* glewlwyd_plugin_callback_add_user)(struct config_plugin * config, json_t * j_user);
  int      (* glewlwyd_plugin_callback_set_user)(struct config_plugin * config, const char * username, json_t * j_user);
  int      (* glewlwyd_plugin_callback_user_update_password)(struct config_plugin * config, const char * username, const char * password);
  int      (* glewlwyd_plugin_callback_delete_user)(struct config_plugin * config, const char * username);

  // Client CRUD
  json_t * (* glewlwyd_plugin_callback_get_client_list)(struct config_plugin * config, const char * pattern, size_t offset, size_t limit);
  json_t * (* glewlwyd_plugin_callback_get_client)(struct config_plugin * config, const char * client_id);
  json_t * (* glewlwyd_plugin_callback_is_client_valid)(struct config_plugin * config, const char * client_id, json_t * j_client, int add);
  int      (* glewlwyd_plugin_callback_add_client)(struct config_plugin * config, json_t * j_client);
  int      (* glewlwyd_plugin_callback_set_client)(struct config_plugin * config, const char * client_id, json_t * j_client);
  int      (* glewlwyd_plugin_callback_delete_client)(struct config_plugin * config, const char * client_id);

  // Register scheme functions
  json_t * (* glewlwyd_plugin_callback_get_scheme_module)(struct config_plugin * config, const char * mod_name);
  json_t * (* glewlwyd_plugin_callback_get_scheme_list)(struct config_plugin * config, const char * username);
  json_t * (* glewlwyd_plugin_callback_scheme_register)(struct config_plugin * config, const char * mod_name, const struct _u_request * http_request, const char * username, json_t * j_scheme_data);
  json_t * (* glewlwyd_plugin_callback_scheme_register_get)(struct config_plugin * config, const char * mod_name, const struct _u_request * http_request, const char * username);
  int      (* glewlwyd_plugin_callback_scheme_deregister)(struct config_plugin * config, const char * mod_name, const char * username);
  int      (* glewlwyd_plugin_callback_scheme_can_use)(struct config_plugin * config, const char * mod_name, const char * username);
  
  // Prometheus metrics functions
  int      (* glewlwyd_plugin_callback_metrics_add_metric)(struct config_plugin * config, const char * name, const char * help);
  int      (* glewlwyd_plugin_callback_metrics_increment_counter)(struct config_plugin * config, const char * name, size_t inc, ...);

  // Misc functions
  char   * (* glewlwyd_callback_get_plugin_external_url)(struct config_plugin * config, const char * name);
  char   * (* glewlwyd_callback_get_login_url)(struct config_plugin * config, const char * client_id, const char * scope_list, const char * callback_url, struct _u_map * additional_parameters);
  char   * (* glewlwyd_callback_generate_hash)(struct config_plugin * config, const char * data);
};

/**
 * Structure given to all module functions that will contain configuration on the
 * application host, and pointer to functions of the application host
 */
struct config_module {
  const char              * external_url;
  const char              * login_url;
  const char              * admin_scope;
  const char              * profile_scope;
  struct _h_connection    * conn;
  digest_algorithm          hash_algorithm;
  struct config_elements  * glewlwyd_config;
  json_t               * (* glewlwyd_module_callback_get_user)(struct config_module * config, const char * username);
  int                    (* glewlwyd_module_callback_set_user)(struct config_module * config, const char * username, json_t * j_user);
  int                    (* glewlwyd_module_callback_check_user_password)(struct config_module * config, const char * username, const char * password);
  json_t               * (* glewlwyd_module_callback_check_user_session)(struct config_module * config, const struct _u_request * request, const char * username);
  int                    (* glewlwyd_module_callback_metrics_add_metric)(struct config_module * config, const char * name, const char * help);
  int                    (* glewlwyd_module_callback_metrics_increment_counter)(struct config_module * config, const char * name, size_t inc, ...);
};

/**
 * Misc functions available in src/misc.c
 */
const char * get_ip_source(const struct _u_request * request);
char * get_client_hostname(const struct _u_request * request);
unsigned char random_at_most(unsigned char max, int nonce);
char * rand_string(char * str, size_t str_size);
char * rand_string_nonce(char * str, size_t str_size);
char * rand_string_from_charset(char * str, size_t str_size, const char * charset);
int rand_code(char * str, size_t str_size);
char * join_json_string_array(json_t * j_array, const char * separator);
int generate_digest(digest_algorithm digest, const char * data, int use_salt, char * out_digest);
int generate_digest_raw(digest_algorithm digest, const unsigned char * data, size_t data_len, unsigned char * out_digest, size_t * out_digest_len);
char * generate_hash(digest_algorithm digest, const char * data);
int generate_digest_pbkdf2(const char * data, unsigned int iterations, const char * salt, char * out_digest);

/**
 * Check if the result json object has a "result" element that is equal to value
 */
int check_result_value(json_t * result, const int value);

/**
 * Modules functions prototypes
 */

/**
 * User functions prototypes
 */
json_t * user_module_load(struct config_module * config);
int      user_module_unload(struct config_module * config);
json_t * user_module_init(struct config_module * config, int readonly, int multiple_passwords, json_t * j_parameters, void ** cls);
int      user_module_close(struct config_module * config, void * cls);
size_t   user_module_count_total(struct config_module * config, const char * pattern, void * cls);
json_t * user_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls);
json_t * user_module_get(struct config_module * config, const char * username, void * cls);
json_t * user_module_get_profile(struct config_module * config, const char * username, void * cls);
json_t * user_module_is_valid(struct config_module * config, const char * username, json_t * j_user, int mode, void * cls);
int      user_module_add(struct config_module * config, json_t * j_user, void * cls);
int      user_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls);
int      user_module_update_profile(struct config_module * config, const char * username, json_t * j_user, void * cls);
int      user_module_delete(struct config_module * config, const char * username, void * cls);
int      user_module_check_password(struct config_module * config, const char * username, const char * password, void * cls);
int      user_module_update_password(struct config_module * config, const char * username, const char ** new_passwords, size_t new_passwords_len, void * cls);

/**
 * User middleware functions prototype
 */
json_t * user_middleware_module_load(struct config_module * config);
int      user_middleware_module_unload(struct config_module * config);
json_t * user_middleware_module_init(struct config_module * config, json_t * j_parameters, void ** cls);
int      user_middleware_module_close(struct config_module * config, void * cls);
int      user_middleware_module_get_list(struct config_module * config, json_t * j_user_list, void * cls);
int      user_middleware_module_get(struct config_module * config, const char * username, json_t * j_user, void * cls);
int      user_middleware_module_get_profile(struct config_module * config, const char * username, json_t * j_user, void * cls);
int      user_middleware_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls);
int      user_middleware_module_delete(struct config_module * config, const char * username, json_t * j_user, void * cls);

/**
 * Client functions prototypes
 */
json_t * client_module_load(struct config_module * config);
int      client_module_unload(struct config_module * config);
json_t * client_module_init(struct config_module * config, int readonly, json_t * j_parameters, void ** cls);
int      client_module_close(struct config_module * config, void * cls);
size_t   client_module_count_total(struct config_module * config, const char * pattern, void * cls);
json_t * client_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls);
json_t * client_module_get(struct config_module * config, const char * client_id, void * cls);
json_t * client_module_is_valid(struct config_module * config, const char * client_id, json_t * j_client, int mode, void * cls);
int      client_module_add(struct config_module * config, json_t * j_client, void * cls);
int      client_module_update(struct config_module * config, const char * client_id, json_t * j_client, void * cls);
int      client_module_delete(struct config_module * config, const char * client_id, void * cls);
int      client_module_check_password(struct config_module * config, const char * client_id, const char * password, void * cls);

/**
 * Scheme functions prototypes
 */
json_t * user_auth_scheme_module_load(struct config_module * config);
int      user_auth_scheme_module_unload(struct config_module * config);
json_t * user_auth_scheme_module_init(struct config_module * config, json_t * j_parameters, const char * mod_name, void ** cls);
int      user_auth_scheme_module_close(struct config_module * config, void * cls);
int      user_auth_scheme_module_can_use(struct config_module * config, const char * username, void * cls);
json_t * user_auth_scheme_module_register(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls);
json_t * user_auth_scheme_module_register_get(struct config_module * config, const struct _u_request * http_request, const char * username, void * cls);
int      user_auth_scheme_module_deregister(struct config_module * config, const char * username, void * cls);
json_t * user_auth_scheme_module_trigger(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_trigger, void * cls);
int      user_auth_scheme_module_validate(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls);
json_t * user_auth_scheme_module_identify(struct config_module * config, const struct _u_request * http_request, json_t * j_scheme_data, void * cls);

/**
 * Plugin functions prototypes
 */
json_t * plugin_module_load(struct config_plugin * config);
int      plugin_module_unload(struct config_plugin * config);
json_t * plugin_module_init(struct config_plugin * config, const char * name, json_t * j_parameters, void ** cls);
int      plugin_module_close(struct config_plugin * config, const char * name, void * cls);

#endif

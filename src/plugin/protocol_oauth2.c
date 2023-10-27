/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 *
 * Legacy (Glewlwyd 1.x) OAuth2 plugin
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

#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <jansson.h>
#include <yder.h>
#include <orcania.h>
#include <ulfius.h>
#include <rhonabwy.h>
#include "glewlwyd-common.h"
#include "glewlwyd_resource.h"

#define OAUTH2_SALT_LENGTH 16

#define GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT 3600
#define GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT 1209600
#define GLEWLWYD_CODE_EXP_DEFAULT 600
#define GLEWLWYD_CODE_CHALLENGE_MAX_LENGTH 128
#define GLEWLWYD_CODE_CHALLENGE_S256_PREFIX "{SHA256}"

#define GLEWLWYD_CHECK_JWT_USERNAME "myrddin"
#define GLEWLWYD_CHECK_JWT_SCOPE    "caledonia"

#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE                       "gpg_code"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE_SCOPE                 "gpg_code_scope"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN              "gpg_refresh_token"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN_SCOPE        "gpg_refresh_token_scope"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN               "gpg_access_token"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN_SCOPE         "gpg_access_token_scope"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION       "gpg_device_authorization"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION_SCOPE "gpg_device_authorization_scope"

#define GLWD_METRICS_OAUTH2_CODE                        "glewlwyd_oauth2_code"
#define GLWD_METRICS_OAUTH2_DEVICE_CODE                 "glewlwyd_oauth2_device_code"
#define GLWD_METRICS_OAUTH2_REFRESH_TOKEN               "glewlwyd_oauth2_refresh_token"
#define GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN           "glewlwyd_oauth2_access_token"
#define GLWD_METRICS_OAUTH2_CLIENT_ACCESS_TOKEN         "glewlwyd_oauth2_client_token"
#define GLWD_METRICS_OAUTH2_UNAUTHORIZED_CLIENT         "glewlwyd_oauth2_unauthorized_client"
#define GLWD_METRICS_OAUTH2_INVALID_CODE                "glewlwyd_oauth2_invalid_code"
#define GLWD_METRICS_OAUTH2_INVALID_DEVICE_CODE         "glewlwyd_oauth2_invalid_device_code"
#define GLWD_METRICS_OAUTH2_INVALID_REFRESH_TOKEN       "glewlwyd_oauth2_invalid_refresh_token"
#define GLWD_METRICS_OAUTH2_INVALID_ACCESS_TOKEN        "glewlwyd_oauth2_invalid_acccess_token"

// Authorization types available
#define GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE                  0
#define GLEWLWYD_AUTHORIZATION_TYPE_IMPLICIT                            1
#define GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS 2
#define GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS                  3
#define GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN                       4
#define GLEWLWYD_AUTHORIZATION_TYPE_DELETE_TOKEN                        5
#define GLEWLWYD_AUTHORIZATION_TYPE_DEVICE_AUTHORIZATION                6

#define GLEWLWYD_DEVICE_AUTH_DEFAUT_EXPIRATION  600
#define GLEWLWYD_DEVICE_AUTH_DEFAUT_INTERVAL    5
#define GLEWLWYD_DEVICE_AUTH_DEVICE_CODE_LENGTH 32
#define GLEWLWYD_DEVICE_AUTH_USER_CODE_LENGTH   8

struct _oauth2_config {
  struct config_plugin             * glewlwyd_config;
  jwt_t                            * jwt_key;
  const char                       * name;
  json_t                           * j_params;
  json_int_t                         access_token_duration;
  json_int_t                         refresh_token_duration;
  json_int_t                         code_duration;
  unsigned short int                 refresh_token_rolling;
  unsigned short int                 auth_type_enabled[5];
  pthread_mutex_t                    insert_lock;
  struct _glewlwyd_resource_config * glewlwyd_resource_config;
  struct _glewlwyd_resource_config * introspect_revoke_resource_config;
};

static json_t * check_parameters (json_t * j_params) {
  json_t * j_element = NULL, * j_return, * j_error = json_array();
  size_t index = 0;
  int ret = G_OK;

  if (j_error != NULL) {
    if (j_params == NULL) {
      json_array_append_new(j_error, json_string("parameters invalid"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "jwt-type") == NULL || !json_is_string(json_object_get(j_params, "jwt-type"))) {
      json_array_append_new(j_error, json_string("jwt-type must be a string and have one of the following values: 'rsa', 'ecdsa', 'sha', 'rsa-pss', 'eddsa'"));
      ret = G_ERROR_PARAM;
    }
    if (0 != o_strcmp("rsa", json_string_value(json_object_get(j_params, "jwt-type"))) &&
        0 != o_strcmp("ecdsa", json_string_value(json_object_get(j_params, "jwt-type"))) &&
        0 != o_strcmp("sha", json_string_value(json_object_get(j_params, "jwt-type"))) &&
        0 != o_strcmp("rsa-pss", json_string_value(json_object_get(j_params, "jwt-type"))) &&
        0 != o_strcmp("eddsa", json_string_value(json_object_get(j_params, "jwt-type")))) {
      json_array_append_new(j_error, json_string("jwt-type must be a string and have one of the following values: 'rsa', 'ecdsa', 'sha', 'rsa-pss', 'eddsa'"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "jwt-key-size") == NULL || !json_is_string(json_object_get(j_params, "jwt-key-size"))) {
      json_array_append_new(j_error, json_string("jwt-key-size must be a string and have one of the following values: '256', '384', '512'"));
      ret = G_ERROR_PARAM;
    }
    if (0 != o_strcmp("256", json_string_value(json_object_get(j_params, "jwt-key-size"))) &&
               0 != o_strcmp("384", json_string_value(json_object_get(j_params, "jwt-key-size"))) &&
               0 != o_strcmp("512", json_string_value(json_object_get(j_params, "jwt-key-size")))) {
      json_array_append_new(j_error, json_string("jwt-key-size must be a string and have one of the following values: '256', '384', '512'"));
      ret = G_ERROR_PARAM;
    }
    if ((0 == o_strcmp("rsa", json_string_value(json_object_get(j_params, "jwt-type"))) ||
                0 == o_strcmp("ecdsa", json_string_value(json_object_get(j_params, "jwt-type")))) &&
               (json_object_get(j_params, "key") == NULL || json_object_get(j_params, "cert") == NULL ||
               !json_is_string(json_object_get(j_params, "key")) || !json_is_string(json_object_get(j_params, "cert")) || json_string_null_or_empty(json_object_get(j_params, "key")) || json_string_null_or_empty(json_object_get(j_params, "cert")))) {
      json_array_append_new(j_error, json_string("Properties 'cert' and 'key' are mandatory and must be strings"));
      ret = G_ERROR_PARAM;
    }
    if (0 == o_strcmp("sha", json_string_value(json_object_get(j_params, "jwt-type"))) &&
              (json_object_get(j_params, "key") == NULL || !json_is_string(json_object_get(j_params, "key")) || json_string_null_or_empty(json_object_get(j_params, "key")))) {
      json_array_append_new(j_error, json_string("Property 'key' is mandatory and must be a string"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "access-token-duration") == NULL || !json_is_integer(json_object_get(j_params, "access-token-duration")) || json_integer_value(json_object_get(j_params, "access-token-duration")) <= 0) {
      json_array_append_new(j_error, json_string("Property 'access-token-duration' is mandatory and must be a non null positive integer"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "refresh-token-duration") == NULL || !json_is_integer(json_object_get(j_params, "refresh-token-duration")) || json_integer_value(json_object_get(j_params, "refresh-token-duration")) <= 0) {
      json_array_append_new(j_error, json_string("Property 'refresh-token-duration' is mandatory and must be a non null positive integer"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "refresh-token-rolling") != NULL && !json_is_boolean(json_object_get(j_params, "refresh-token-rolling"))) {
      json_array_append_new(j_error, json_string("Property 'refresh-token-rolling' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-code-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-code-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-code-enabled' is mandatory and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-implicit-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-implicit-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-implicit-enabled' is mandatory and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-password-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-password-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-password-enabled' is mandatory and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-client-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-client-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-client-enabled' is mandatory and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-device-enabled") != NULL && !json_is_boolean(json_object_get(j_params, "auth-type-device-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-device-enabled' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-refresh-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-refresh-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-refresh-enabled' is mandatory and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "scope") != NULL) {
      if (!json_is_array(json_object_get(j_params, "scope"))) {
        json_array_append_new(j_error, json_string("Property 'scope' is optional and must be an array"));
        ret = G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_params, "scope"), index, j_element) {
          if (!json_is_object(j_element)) {
            json_array_append_new(j_error, json_string("'scope' element must be a JSON object"));
            ret = G_ERROR_PARAM;
          } else {
            if (json_object_get(j_element, "name") == NULL || !json_is_string(json_object_get(j_element, "name")) || json_string_null_or_empty(json_object_get(j_element, "name"))) {
              json_array_append_new(j_error, json_string("'scope' element must have a property 'name' of type string and non empty"));
              ret = G_ERROR_PARAM;
            } else if (json_object_get(j_element, "refresh-token-rolling") != NULL && !json_is_boolean(json_object_get(j_element, "refresh-token-rolling"))) {
              json_array_append_new(j_error, json_string("'scope' element can have a property 'refresh-token-rolling' of type boolean"));
              ret = G_ERROR_PARAM;
            } else if (json_object_get(j_element, "refresh-token-duration") != NULL && (!json_is_integer(json_object_get(j_element, "refresh-token-duration")) || json_integer_value(json_object_get(j_element, "refresh-token-duration")) < 0)) {
              json_array_append_new(j_error, json_string("'scope' element can have a property 'refresh-token-duration' of type integer and non null positive value"));
              ret = G_ERROR_PARAM;
            }
          }
        }
      }
    } else if (json_object_get(j_params, "additional-parameters") != NULL) {
      if (!json_is_array(json_object_get(j_params, "additional-parameters"))) {
        json_array_append_new(j_error, json_string("Property 'additional-parameters' is optional and must be an array"));
        ret = G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_params, "additional-parameters"), index, j_element) {
          if (!json_is_object(j_element)) {
            json_array_append_new(j_error, json_string("'additional-parameters' element must be a JSON object"));
            ret = G_ERROR_PARAM;
          } else {
            if ((json_object_get(j_element, "user-parameter") == NULL || !json_is_string(json_object_get(j_element, "user-parameter"))) &&
                (json_object_get(j_element, "client-parameter") == NULL || !json_is_string(json_object_get(j_element, "client-parameter")))) {
              json_array_append_new(j_error, json_string("'additional-parameters' element must have a property 'user-parameter' or 'client-parameter' of type string"));
              ret = G_ERROR_PARAM;
            } else if (json_object_get(j_element, "token-parameter") == NULL || !json_is_string(json_object_get(j_element, "token-parameter")) || json_string_null_or_empty(json_object_get(j_element, "token-parameter"))) {
              json_array_append_new(j_error, json_string("'additional-parameters' element must have a property 'token-parameter' of type string and non empty, forbidden values are: 'username', 'salt', 'type', 'iat', 'expires_in', 'scope'"));
              ret = G_ERROR_PARAM;
            } else if (0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "username") ||
                       0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "salt") ||
                       0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "type") ||
                       0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "iat") ||
                       0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "expires_in") ||
                       0 == o_strcmp(json_string_value(json_object_get(j_element, "token-parameter")), "scope")) {
              json_array_append_new(j_error, json_string("'additional-parameters' element must have a property 'token-parameter' of type string and non empty, forbidden values are: 'username', 'salt', 'type', 'iat', 'expires_in', 'scope'"));
              ret = G_ERROR_PARAM;
            }
          }
        }
      }
    }
    if (json_object_get(j_params, "pkce-allowed") != NULL && !json_is_boolean(json_object_get(j_params, "pkce-allowed"))) {
      json_array_append_new(j_error, json_string("Property 'pkce-allowed' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "pkce-method-plain-allowed") != NULL && json_object_get(j_params, "pkce-allowed") == json_true() && !json_is_boolean(json_object_get(j_params, "pkce-method-plain-allowed"))) {
      json_array_append_new(j_error, json_string("Property 'pkce-method-plain-allowed' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "introspection-revocation-allowed") != NULL && !json_is_boolean(json_object_get(j_params, "introspection-revocation-allowed"))) {
      json_array_append_new(j_error, json_string("Property 'introspection-revocation-allowed' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "introspection-revocation-allowed") == json_true()) {
      if (json_object_get(j_params, "introspection-revocation-auth-scope") != NULL && !json_is_array(json_object_get(j_params, "introspection-revocation-auth-scope"))) {
        json_array_append_new(j_error, json_string("Property 'introspection-revocation-auth-scope' is optional and must be a JSON array of strings, maximum 128 characters"));
        ret = G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_params, "introspection-revocation-auth-scope"), index, j_element) {
          if (!json_is_string(j_element) || json_string_length(j_element) > 128) {
            json_array_append_new(j_error, json_string("Property 'introspection-revocation-auth-scope' is optional and must be a JSON array of strings, maximum 128 characters"));
            ret = G_ERROR_PARAM;
          }
        }
      }
      if (json_object_get(j_params, "introspection-revocation-allow-target-client") != NULL && !json_is_boolean(json_object_get(j_params, "introspection-revocation-allow-target-client"))) {
        json_array_append_new(j_error, json_string("Property 'introspection-revocation-allow-target-client' is optional and must be a boolean"));
        ret = G_ERROR_PARAM;
      }
    }
    if (json_object_get(j_params, "auth-type-device-enabled") == json_true()) {
      if (json_object_get(j_params, "device-authorization-expiration") != NULL && json_integer_value(json_object_get(j_params, "device-authorization-expiration")) <= 0) {
        json_array_append_new(j_error, json_string("Property 'device-authorization-expiration' is optional and must be a non null positive integer"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "device-authorization-interval") != NULL && json_integer_value(json_object_get(j_params, "device-authorization-interval")) <= 0) {
        json_array_append_new(j_error, json_string("Property 'device-authorization-interval' is optional and must be a non null positive integer"));
        ret = G_ERROR_PARAM;
      }
    }
    if (json_array_size(j_error) && ret == G_ERROR_PARAM) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{si}", "result", ret);
    }
    json_decref(j_error);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_parameters oauth2 - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

/**
 *
 * Generates a query string based on url and post parameters of a request
 * Returned value must be o_free'd after use
 *
 */
static char * generate_query_parameters(struct _u_map * map_url, struct _u_map * map_post_body) {
  char * query = NULL, * param, * tmp, * value;
  const char ** keys;
  int i;

  if (map_url == NULL && map_post_body == NULL) {
    return NULL;
  } else {
    if (map_url != NULL) {
      keys = u_map_enum_keys(map_url);
      for (i=0; keys[i] != NULL; i++) {
        value = ulfius_url_encode((char *)u_map_get(map_url, keys[i]));
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
    }

    if (map_post_body != NULL) {
      keys = u_map_enum_keys(map_post_body);
      for (i=0; keys[i] != NULL; i++) {
        value = ulfius_url_encode((char *)u_map_get(map_post_body, keys[i]));
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
    }
  }

  return query;
}

static int serialize_access_token(struct _oauth2_config * config, uint auth_type, json_int_t gpgr_id, const char * username, const char * client_id, const char * scope_list, time_t now, const char * issued_for, const char * user_agent, const char * access_token) {
  json_t * j_query, * j_last_id;
  int res, ret, i;
  char * issued_at_clause, ** scope_array = NULL, * access_token_hash = NULL;

  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - oauth2 - Error pthread_mutex_lock");
    ret = G_ERROR;
  } else {
    if ((access_token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, access_token)) != NULL) {
      if (issued_for != NULL && now > 0) {
        if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
          issued_at_clause = msprintf("FROM_UNIXTIME(%u)", (now));
        } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
          issued_at_clause = msprintf("TO_TIMESTAMP(%u)", (now));
        } else { // HOEL_DB_TYPE_SQLITE
          issued_at_clause = msprintf("%u", (now));
        }
        j_query = json_pack("{sss{sssisososos{ss}ssssss}}",
                            "table",
                            GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN,
                            "values",
                              "gpga_plugin_name",
                              config->name,
                              "gpga_authorization_type",
                              auth_type,
                              "gpgr_id",
                              gpgr_id?json_integer(gpgr_id):json_null(),
                              "gpga_username",
                              username!=NULL?json_string(username):json_null(),
                              "gpga_client_id",
                              client_id!=NULL?json_string(client_id):json_null(),
                              "gpga_issued_at",
                                "raw",
                                issued_at_clause,
                              "gpga_issued_for",
                              issued_for,
                              "gpga_user_agent",
                              user_agent!=NULL?user_agent:"",
                              "gpga_token_hash",
                              access_token_hash);
        o_free(issued_at_clause);
        res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
          if (j_last_id != NULL) {
            if (split_string_remove_duplicates(scope_list, " ", &scope_array) > 0) {
              j_query = json_pack("{sss[]}",
                                  "table",
                                  GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN_SCOPE,
                                  "values");
              if (j_query != NULL) {
                for (i=0; scope_array[i] != NULL; i++) {
                  json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOss}", "gpga_id", j_last_id, "gpgas_scope", scope_array[i]));
                }
                res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
                json_decref(j_query);
                if (res == H_OK) {
                  ret = G_OK;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - oauth2 - Error executing j_query (2)");
                  config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
                  ret = G_ERROR_DB;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - oauth2 - Error json_pack");
                ret = G_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - oauth2 - Error split_string_remove_duplicates");
              ret = G_ERROR;
            }
            free_string_array(scope_array);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - oauth2 - Error h_last_insert_id");
            config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
            ret = G_ERROR_DB;
          }
          json_decref(j_last_id);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - oauth2 - Error executing j_query (1)");
          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          ret = G_ERROR_DB;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
      o_free(access_token_hash);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "serialize_access_token - oauth2 - Error glewlwyd_callback_generate_hash");
      ret = G_ERROR;
    }
    pthread_mutex_unlock(&config->insert_lock);
  }
  return ret;
}

/**
 * Generates a client_access_token from the specified parameters that are considered valid
 */
static char * generate_client_access_token(struct _oauth2_config * config, const char * client_id, const char * scope_list, json_t * j_client, time_t now, const char * ip_source) {
  jwt_t * jwt;
  char * token = NULL, * property = NULL;
  char salt[OAUTH2_SALT_LENGTH + 1] = {0};
  json_t * j_element = NULL, * j_value;
  size_t index = 0, index_p = 0;

  jwt = r_jwt_copy(config->jwt_key);
  if (jwt != NULL) {
    // Build jwt payload
    rand_string_nonce(salt, OAUTH2_SALT_LENGTH);
    if (json_object_get(config->j_params, "additional-parameters") != NULL && j_client != NULL) {
      json_array_foreach(json_object_get(config->j_params, "additional-parameters"), index, j_element) {
        if (!json_string_null_or_empty(json_object_get(j_element, "client-parameter"))) {
          if (json_is_string(json_object_get(j_client, json_string_value(json_object_get(j_element, "client-parameter")))) && !json_string_null_or_empty(json_object_get(j_client, json_string_value(json_object_get(j_element, "client-parameter"))))) {
            r_jwt_set_claim_str_value(jwt, json_string_value(json_object_get(j_element, "token-parameter")), json_string_value(json_object_get(j_client, json_string_value(json_object_get(j_element, "client-parameter")))));
          } else if (json_is_array(json_object_get(j_client, json_string_value(json_object_get(j_element, "client-parameter"))))) {
            json_array_foreach(json_object_get(j_client, json_string_value(json_object_get(j_element, "client-parameter"))), index_p, j_value) {
              property = mstrcatf(property, ",%s", json_string_value(j_value));
            }
            if (!o_strnullempty(property)) {
              r_jwt_set_claim_str_value(jwt, json_string_value(json_object_get(j_element, "token-parameter")), property+1); // Skip first ','
            } else {
              r_jwt_set_claim_str_value(jwt, json_string_value(json_object_get(j_element, "token-parameter")), "");
            }
            o_free(property);
            property = NULL;
          }
        }
      }
    }
    r_jwt_set_claim_str_value(jwt, "salt", salt);
    r_jwt_set_claim_str_value(jwt, "client_id", client_id);
    r_jwt_set_claim_str_value(jwt, "type", "client_token");
    r_jwt_set_claim_str_value(jwt, "scope", scope_list);
    r_jwt_set_claim_int_value(jwt, "iat", now);
    r_jwt_set_claim_int_value(jwt, "expires_in", config->access_token_duration);
    r_jwt_set_claim_int_value(jwt, "exp", (((json_int_t)now)+config->access_token_duration));
    r_jwt_set_claim_int_value(jwt, "nbf", now);
    token = r_jwt_serialize_signed(jwt, NULL, 0);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_client_access_token - oauth2 - Error generating token");
    } else {
      y_log_message(Y_LOG_LEVEL_INFO, "Event oauth2 - Plugin '%s' - Access token generated for client '%s' with scope list '%s', origin: %s", config->name, client_id, scope_list, ip_source);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_client_access_token - oauth2 - Error cloning jwt");
  }
  r_jwt_free(jwt);
  return token;
}

static char * generate_access_token(struct _oauth2_config * config, const char * username, const char * client_id, json_t * j_user, const char * scope_list, time_t now, const char * ip_source) {
  char salt[OAUTH2_SALT_LENGTH + 1] = {0};
  jwt_t * jwt = NULL;
  char * token = NULL, * property = NULL;
  json_t * j_element = NULL, * j_value;
  size_t index = 0, index_p = 0;

  if ((jwt = r_jwt_copy(config->jwt_key)) != NULL) {
    rand_string_nonce(salt, OAUTH2_SALT_LENGTH);
    if (json_object_get(config->j_params, "additional-parameters") != NULL && j_user != NULL) {
      json_array_foreach(json_object_get(config->j_params, "additional-parameters"), index, j_element) {
        if (!json_string_null_or_empty(json_object_get(j_element, "user-parameter"))) {
          if (json_is_string(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter")))) && !json_string_null_or_empty(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))))) {
            r_jwt_set_claim_str_value(jwt, json_string_value(json_object_get(j_element, "token-parameter")), json_string_value(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter")))));
          } else if (json_is_array(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))))) {
            json_array_foreach(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))), index_p, j_value) {
              property = mstrcatf(property, ",%s", json_string_value(j_value));
            }
            if (!o_strnullempty(property)) {
              r_jwt_set_claim_str_value(jwt, json_string_value(json_object_get(j_element, "token-parameter")), property+1); // Skip first ','
            } else {
              r_jwt_set_claim_str_value(jwt, json_string_value(json_object_get(j_element, "token-parameter")), "");
            }
            o_free(property);
            property = NULL;
          }
        }
      }
    }
    r_jwt_set_claim_str_value(jwt, "username", username);
    r_jwt_set_claim_str_value(jwt, "salt", salt);
    r_jwt_set_claim_str_value(jwt, "type", "access_token");
    r_jwt_set_claim_int_value(jwt, "iat", now);
    r_jwt_set_claim_int_value(jwt, "expires_in", config->access_token_duration);
    r_jwt_set_claim_int_value(jwt, "exp", (((json_int_t)now)+config->access_token_duration));
    r_jwt_set_claim_int_value(jwt, "nbf", now);
    if (scope_list != NULL) {
      r_jwt_set_claim_str_value(jwt, "scope", scope_list);
    }
    token = r_jwt_serialize_signed(jwt, NULL, 0);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_access_token - oauth2 - oauth2 - Error jwt_encode_str");
    } else {
      y_log_message(Y_LOG_LEVEL_INFO, "Event oauth2 - Plugin '%s' - Access token generated for client '%s' granted by user '%s' with scope list '%s', origin: %s", config->name, client_id, username, scope_list, ip_source);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_access_token - oauth2 - Error jwt_dup");
  }
  r_jwt_free(jwt);
  return token;
}

static json_t * serialize_refresh_token(struct _oauth2_config * config, uint auth_type, json_int_t gpgc_id, const char * username, const char * client_id, const char * scope_list, time_t now, json_int_t duration, uint rolling, const char * token, const char * issued_for, const char * user_agent) {
  char * token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token);
  json_t * j_query, * j_return, * j_last_id;
  int res, i;
  char * issued_at_clause, * expires_at_clause, * last_seen_clause, ** scope_array = NULL;

  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - oauth2 - Error pthread_mutex_lock");
    j_return = json_pack("{si}", "result", G_ERROR);
  } else {
    if (token_hash != NULL && username != NULL && issued_for != NULL && now > 0 && duration > 0) {
      json_error_t error;
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        issued_at_clause = msprintf("FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        issued_at_clause = msprintf("TO_TIMESTAMP(%u)", (now));
      } else { // HOEL_DB_TYPE_SQLITE
        issued_at_clause = msprintf("%u", (now));
      }
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        last_seen_clause = msprintf("FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        last_seen_clause = msprintf("TO_TIMESTAMP(%u)", (now));
      } else { // HOEL_DB_TYPE_SQLITE
        last_seen_clause = msprintf("%u", (now));
      }
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (time_t)duration));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (time_t)duration ));
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("%u", (now + (time_t)duration));
      }
      j_query = json_pack_ex(&error, 0, "{sss{ss si so ss so s{ss} s{ss} s{ss} sI si ss ss ss}}",
                          "table",
                          GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                          "values",
                            "gpgr_plugin_name",
                            config->name,
                            "gpgr_authorization_type",
                            auth_type,
                            "gpgc_id",
                            gpgc_id?json_integer(gpgc_id):json_null(),
                            "gpgr_username",
                            username,
                            "gpgr_client_id",
                            client_id!=NULL?json_string(client_id):json_null(),
                            "gpgr_issued_at",
                              "raw",
                              issued_at_clause,
                            "gpgr_last_seen",
                              "raw",
                              last_seen_clause,
                            "gpgr_expires_at",
                              "raw",
                              expires_at_clause,
                            "gpgr_duration",
                            duration,
                            "gpgr_rolling_expiration",
                            rolling,
                            "gpgr_token_hash",
                            token_hash,
                            "gpgr_issued_for",
                            issued_for,
                            "gpgr_user_agent",
                            user_agent!=NULL?user_agent:"");
      o_free(issued_at_clause);
      o_free(expires_at_clause);
      o_free(last_seen_clause);
      res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
        if (j_last_id != NULL) {
          if (split_string_remove_duplicates(scope_list, " ", &scope_array) > 0) {
            j_query = json_pack("{sss[]}",
                                "table",
                                GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN_SCOPE,
                                "values");
            if (j_query != NULL) {
              for (i=0; scope_array[i] != NULL; i++) {
                json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOss}", "gpgr_id", j_last_id, "gpgrs_scope", scope_array[i]));
              }
              res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
              json_decref(j_query);
              if (res == H_OK) {
                j_return = json_pack("{sisO}", "result", G_OK, "gpgr_id", j_last_id);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - oauth2 - Error executing j_query (2)");
                config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
                j_return = json_pack("{si}", "result", G_ERROR_DB);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - oauth2 - Error json_pack");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - oauth2 - Error split_string_remove_duplicates");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          free_string_array(scope_array);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - oauth2 - Error h_last_insert_id");
          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        json_decref(j_last_id);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "serialize_refresh_token - oauth2 - Error executing j_query (1)");
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    }
    o_free(token_hash);
    pthread_mutex_unlock(&config->insert_lock);
  }
  return j_return;
}

static char * generate_refresh_token(struct _oauth2_config * config, const char * client_id, const char * username, const char * scope_list, time_t now, const char * ip_source) {
  jwt_t * jwt;
  char * token = NULL;
  char salt[OAUTH2_SALT_LENGTH + 1] = {0};

  if ((jwt = r_jwt_copy(config->jwt_key)) != NULL) {
    // Build jwt payload
    rand_string_nonce(salt, OAUTH2_SALT_LENGTH);
    r_jwt_set_claim_str_value(jwt, "salt", salt);
    r_jwt_set_claim_str_value(jwt, "username", username);
    r_jwt_set_claim_str_value(jwt, "type", "refresh_token");
    r_jwt_set_claim_int_value(jwt, "iat", now);
    if (scope_list != NULL) {
      r_jwt_set_claim_str_value(jwt, "scope", scope_list);
    }
    if (client_id != NULL) {
      r_jwt_set_claim_str_value(jwt, "client_id", client_id);
    }
    token = r_jwt_serialize_signed(jwt, NULL, 0);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_refresh_token - oauth2 - generating token");
    } else {
      y_log_message(Y_LOG_LEVEL_INFO, "Event oauth2 - Plugin '%s' - Refresh token generated for client '%s' granted by user '%s' with scope list '%s', origin: %s", config->name, client_id, username, scope_list, ip_source);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_refresh_token - Error cloning jwt");
  }
  r_jwt_free(jwt);
  return token;
}

static int is_authorization_type_enabled(struct _oauth2_config * config, uint authorization_type) {
  return (authorization_type <= 4)?config->auth_type_enabled[authorization_type]:0;
}

static json_t * check_client_valid(struct _oauth2_config * config, const char * client_id, const char * client_header_login, const char * client_header_password, const char * redirect_uri, unsigned short authorization_type, int implicit_flow, const char * ip_source) {
  json_t * j_client, * j_element = NULL, * j_return;
  int uri_found, authorization_type_enabled;
  size_t index = 0;

  if (client_id == NULL) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "check_client_valid - oauth2 - Error client_id is NULL, origin: %s", ip_source);
    return json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (client_header_login != NULL && 0 != o_strcmp(client_header_login, client_id)) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "check_client_valid - oauth2 - Error, client_id specified is different from client_id in the basic auth header, origin: %s", ip_source);
    return json_pack("{si}", "result", G_ERROR_PARAM);
  }
  j_client = config->glewlwyd_config->glewlwyd_callback_check_client_valid(config->glewlwyd_config, client_id, client_header_password);
  if (check_result_value(j_client, G_OK)) {
    if (!implicit_flow && client_header_password == NULL && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "check_client_valid - oauth2 - Error, confidential client must be authentified with its password, origin: %s", ip_source);
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    } else {
      if (redirect_uri != NULL) {
        uri_found = 0;
        json_array_foreach(json_object_get(json_object_get(j_client, "client"), "redirect_uri"), index, j_element) {
          if (0 == o_strcmp(json_string_value(j_element), redirect_uri)) {
            uri_found = 1;
          }
        }
      } else {
        uri_found = 1;
      }

      authorization_type_enabled = 0;
      json_array_foreach(json_object_get(json_object_get(j_client, "client"), "authorization_type"), index, j_element) {
        if (authorization_type == GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE && 0 == o_strcmp(json_string_value(j_element), "code")) {
          authorization_type_enabled = 1;
        } else if (authorization_type == GLEWLWYD_AUTHORIZATION_TYPE_IMPLICIT && 0 == o_strcmp(json_string_value(j_element), "token")) {
          authorization_type_enabled = 1;
        } else if (authorization_type == GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS && 0 == o_strcmp(json_string_value(j_element), "password")) {
          authorization_type_enabled = 1;
          uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
        } else if (authorization_type == GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN && 0 == o_strcmp(json_string_value(j_element), "refresh_token")) {
          authorization_type_enabled = 1;
          uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
        } else if (authorization_type == GLEWLWYD_AUTHORIZATION_TYPE_DELETE_TOKEN && 0 == o_strcmp(json_string_value(j_element), "delete_token")) {
          authorization_type_enabled = 1;
          uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
        } else if (authorization_type == GLEWLWYD_AUTHORIZATION_TYPE_DEVICE_AUTHORIZATION && 0 == o_strcmp(json_string_value(j_element), "device_authorization")) {
          authorization_type_enabled = 1;
          uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
        }
      }
      if (!uri_found) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_client_valid - oauth2 - Error, redirect_uri '%s' is invalid for the client '%s', origin: %s", redirect_uri, client_id, ip_source);
      }
      if (!authorization_type_enabled) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_client_valid - oauth2 - Error, authorization type is not enabled for the client '%s', origin: %s", client_id, ip_source);
      }
      if (uri_found && authorization_type_enabled) {
        j_return = json_pack("{sisO}", "result", G_OK, "client", json_object_get(j_client, "client"));
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "check_client_valid - oauth2 - Error, client '%s' is invalid, origin: %s", client_id, ip_source);
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  json_decref(j_client);
  return j_return;
}

static char * generate_authorization_code(struct _oauth2_config * config, const char * username, const char * client_id, const char * scope_list, const char * redirect_uri, const char * issued_for, const char * user_agent, const char * code_challenge) {
  char * code = NULL, * code_hash = NULL, * expiration_clause, ** scope_array = NULL;
  json_t * j_query, * j_code_id;
  int res, i;
  time_t now;

  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - oauth2 - Error pthread_mutex_lock");
  } else {
    code = o_malloc(33);
    if (code != NULL) {
      if (rand_string_nonce(code, 32) != NULL) {
        code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code);
        if (code_hash != NULL) {
          time(&now);
          if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
            expiration_clause = msprintf("FROM_UNIXTIME(%u)", (now + (time_t)config->code_duration ));
          } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
            expiration_clause = msprintf("TO_TIMESTAMP(%u)", (now + (time_t)config->code_duration ));
          } else { // HOEL_DB_TYPE_SQLITE
            expiration_clause = msprintf("%u", (now + (time_t)config->code_duration ));
          }
          j_query = json_pack("{sss{sssssssssssssss{ss}ss}}",
                              "table",
                              GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE,
                              "values",
                                "gpgc_plugin_name",
                                config->name,
                                "gpgc_username",
                                username,
                                "gpgc_client_id",
                                client_id,
                                "gpgc_redirect_uri",
                                redirect_uri,
                                "gpgc_code_hash",
                                code_hash,
                                "gpgc_issued_for",
                                issued_for,
                                "gpgc_user_agent",
                                user_agent!=NULL?user_agent:"",
                                "gpgc_expires_at",
                                  "raw",
                                  expiration_clause,
                                "gpgc_code_challenge",
                                code_challenge);
          o_free(expiration_clause);
          res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
          json_decref(j_query);
          if (res != H_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - oauth2 - Error executing j_query (1)");
            o_free(code);
            code = NULL;
          } else {
            if (scope_list != NULL) {
              j_code_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
              if (j_code_id != NULL) {
                j_query = json_pack("{sss[]}",
                                    "table",
                                    GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE_SCOPE,
                                    "values");
                if (split_string_remove_duplicates(scope_list, " ", &scope_array) > 0) {
                  for (i=0; scope_array[i] != NULL; i++) {
                    json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOss}", "gpgc_id", j_code_id, "gpgcs_scope", scope_array[i]));
                  }
                  res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
                  json_decref(j_query);
                  if (res != H_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - oauth2 - Error executing j_query (2)");
                    o_free(code);
                    code = NULL;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - oauth2 - Error split_string_remove_duplicates");
                  o_free(code);
                  code = NULL;
                }
                free_string_array(scope_array);
                json_decref(j_code_id);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - oauth2 - Error h_last_insert_id");
                o_free(code);
                code = NULL;
              }
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - oauth2 - Error glewlwyd_callback_generate_hash");
          o_free(code);
          code = NULL;
        }
        o_free(code_hash);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - oauth2 - Error rand_string");
        o_free(code);
        code = NULL;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - oauth2 - Error allocating resources for code");
    }
    pthread_mutex_unlock(&config->insert_lock);
  }

  return code;
}

static char * get_login_url(struct _oauth2_config * config, const struct _u_request * request, const char * url, const char * client_id, const char * scope_list, struct _u_map * additional_parameters) {
  char * plugin_url = config->glewlwyd_config->glewlwyd_callback_get_plugin_external_url(config->glewlwyd_config, json_string_value(json_object_get(config->j_params, "name"))),
       * url_params = generate_query_parameters(request->map_url, NULL),
       * url_callback = msprintf("%s/%s%s%s", plugin_url, url, o_strlen(url_params)?"?":"", url_params),
       * login_url = config->glewlwyd_config->glewlwyd_callback_get_login_url(config->glewlwyd_config, client_id, scope_list, url_callback, additional_parameters);
  o_free(plugin_url);
  o_free(url_params);
  o_free(url_callback);
  return login_url;
}

static json_t * get_scope_parameters(struct _oauth2_config * config, const char * scope) {
  json_t * j_element = NULL, * j_return = NULL;
  size_t index = 0;

  json_array_foreach(json_object_get(config->j_params, "scope"), index, j_element) {
    if (0 == o_strcmp(scope, json_string_value(json_object_get(j_element, "name")))) {
      j_return = json_incref(j_element);
    }
  }
  return j_return;
}

static int disable_authorization_code(struct _oauth2_config * config, json_int_t gpgc_id) {
  json_t * j_query;
  int res;

  j_query = json_pack("{sss{si}s{sssI}}",
                      "table",
                      GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE,
                      "set",
                        "gpgc_enabled",
                        0,
                      "where",
                        "gpgc_plugin_name",
                        config->name,
                        "gpgc_id",
                        gpgc_id);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "disable_authorization_code - oauth2 - Error executing j_query");
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    return G_ERROR_DB;
  }
}

/**
 * Characters allowed according to RFC 7636
 * [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 */
static int is_pkce_char_valid(const char * code_challenge) {
  size_t i;

  if (o_strlen(code_challenge) >= 43 && o_strlen(code_challenge) <= 128) {
    for (i=0; code_challenge[i] != '\0'; i++) {
      if (code_challenge[i] == 0x2d || code_challenge[i] == 0x2e || code_challenge[i] == 0x5f || code_challenge[i] == 0x7e || (code_challenge[i] >= 0x30 && code_challenge[i] <= 0x39) || (code_challenge[i] >= 0x41 && code_challenge[i] <= 0x5a) || (code_challenge[i] >= 0x61 && code_challenge[i] <= 0x7a)) {
        continue;
      } else {
        return 0;
      }
    }
    return 1;
  } else {
    return 0;
  }
}

static int validate_code_challenge(json_t * j_result_code, const char * code_verifier) {
  int ret;
  unsigned char code_verifier_hash[32] = {0}, code_verifier_hash_b64[64] = {0};
  size_t code_verifier_hash_len = 32, code_verifier_hash_b64_len = 0;
  gnutls_datum_t key_data;

  if (!json_string_null_or_empty(json_object_get(j_result_code, "code_challenge"))) {
    if (is_pkce_char_valid(code_verifier)) {
      if (0 == o_strncmp(GLEWLWYD_CODE_CHALLENGE_S256_PREFIX, json_string_value(json_object_get(j_result_code, "code_challenge")), o_strlen(GLEWLWYD_CODE_CHALLENGE_S256_PREFIX))) {
        key_data.data = (unsigned char *)code_verifier;
        key_data.size = (unsigned int)o_strlen(code_verifier);
        if (gnutls_fingerprint(GNUTLS_DIG_SHA256, &key_data, code_verifier_hash, &code_verifier_hash_len) == GNUTLS_E_SUCCESS) {
          if (o_base64url_encode(code_verifier_hash, code_verifier_hash_len, code_verifier_hash_b64, &code_verifier_hash_b64_len)) {
            code_verifier_hash_b64[code_verifier_hash_b64_len] = '\0';
            if (0 == o_strcmp(json_string_value(json_object_get(j_result_code, "code_challenge"))+o_strlen(GLEWLWYD_CODE_CHALLENGE_S256_PREFIX), (const char *)code_verifier_hash_b64)) {
              ret = G_OK;
            } else {
              ret = G_ERROR_UNAUTHORIZED;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "validate_code_challenge - Error o_base64url_encode");
            ret = G_ERROR;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "validate_code_challenge - Error gnutls_fingerprint");
          ret = G_ERROR;
        }
      } else {
        if (0 == o_strcmp(json_string_value(json_object_get(j_result_code, "code_challenge")), code_verifier)) {
          ret = G_OK;
        } else {
          ret = G_ERROR_PARAM;
        }
      }
    } else {
      ret = G_ERROR_PARAM;
    }
  } else {
    ret = G_OK;
  }
  return ret;
}

static int revoke_tokens_from_code(struct _oauth2_config * config, json_int_t gpgc_id, const char * ip_source) {
  int ret, res;
  char * query;
  json_t * j_result, * j_result_r, * j_element = NULL;
  size_t index = 0;

  query = msprintf("SELECT gpga_client_id AS client_id FROM " GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN " WHERE gpgr_id IN (SELECT gpgr_id FROM " GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN " WHERE gpgc_id=%" JSON_INTEGER_FORMAT ") AND gpga_enabled=1", gpgc_id);
  res = h_execute_query_json(config->glewlwyd_config->glewlwyd_config->conn, query, &j_result);
  o_free(query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      y_log_message(Y_LOG_LEVEL_INFO, "Event oauth2 - Plugin '%s' - Access token generated for client '%s' revoked, origin: %s", config->name, json_string_value(json_object_get(j_element, "client_id")), ip_source);
    }
    json_decref(j_result);
    query = msprintf("SELECT gpgr_client_id AS client_id FROM " GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN " WHERE gpgc_id=%" JSON_INTEGER_FORMAT " AND gpgr_enabled=1", gpgc_id);
    res = h_execute_query_json(config->glewlwyd_config->glewlwyd_config->conn, query, &j_result_r);
    o_free(query);
    if (res == H_OK) {
      if (json_array_size(j_result_r)) {
        y_log_message(Y_LOG_LEVEL_INFO, "Event oauth2 - Plugin '%s' - Refresh token generated for client '%s' revoked, origin: %s", config->name, json_string_value(json_object_get(json_array_get(j_result_r, 0), "client_id")), ip_source);
      }
      json_decref(j_result_r);
      query = msprintf("UPDATE " GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN " SET gpga_enabled='0' WHERE gpgr_id IN (SELECT gpgr_id FROM " GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN " WHERE gpgc_id=%" JSON_INTEGER_FORMAT ")", gpgc_id);
      res = h_execute_query(config->glewlwyd_config->glewlwyd_config->conn, query, NULL, H_OPTION_EXEC);
      o_free(query);
      if (res == H_OK) {
        query = msprintf("UPDATE " GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN " SET gpgr_enabled='0' WHERE gpgc_id=%" JSON_INTEGER_FORMAT, gpgc_id);
        res = h_execute_query(config->glewlwyd_config->glewlwyd_config->conn, query, NULL, H_OPTION_EXEC);
        o_free(query);
        if (res == H_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "revoke_tokens_from_code - oauth2 - Error executing query (4)");
          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          ret = G_ERROR_DB;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "revoke_tokens_from_code - oauth2 - Error executing query (3)");
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        ret = G_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc revoke_tokens_from_code - Error executing query (2)");
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
      ret = G_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc revoke_tokens_from_code - Error executing query (1)");
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    ret = G_ERROR_DB;
  }
  return ret;
}

static json_t * validate_authorization_code(struct _oauth2_config * config, const char * code, const char * client_id, const char * redirect_uri, const char * code_verifier, const char * ip_source) {
  char * code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code), * expiration_clause = NULL, * scope_list = NULL, * tmp;
  json_t * j_query, * j_result = NULL, * j_result_scope = NULL, * j_return, * j_element = NULL, * j_scope_param;
  int res;
  size_t index = 0;
  json_int_t maximum_duration = config->refresh_token_duration, maximum_duration_override = -1;
  int rolling_refresh = config->refresh_token_rolling, rolling_refresh_override = -1;

  if (code_hash != NULL) {
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expiration_clause = o_strdup("> NOW()");
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expiration_clause = o_strdup("> NOW()");
    } else { // HOEL_DB_TYPE_SQLITE
      expiration_clause = o_strdup("> (strftime('%s','now'))");
    }
    j_query = json_pack("{sss[ssss]s{sssssssss{ssss}}}",
                        "table",
                        GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE,
                        "columns",
                          "gpgc_username AS username",
                          "gpgc_id",
                          "gpgc_code_challenge AS code_challenge",
                          "gpgc_enabled AS enabled",
                        "where",
                          "gpgc_plugin_name",
                          config->name,
                          "gpgc_client_id",
                          client_id,
                          "gpgc_redirect_uri",
                          redirect_uri,
                          "gpgc_code_hash",
                          code_hash,
                          "gpgc_expires_at",
                            "operator",
                            "raw",
                            "value",
                            expiration_clause);
    o_free(expiration_clause);
    res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        if (json_integer_value(json_object_get(json_array_get(j_result, 0), "enabled"))) {
          if ((res = validate_code_challenge(json_array_get(j_result, 0), code_verifier)) == G_OK) {
            j_query = json_pack("{sss[s]s{sO}}",
                                "table",
                                GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE_SCOPE,
                                "columns",
                                  "gpgcs_scope AS name",
                                "where",
                                  "gpgc_id",
                                  json_object_get(json_array_get(j_result, 0), "gpgc_id"));
            res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result_scope, NULL);
            json_decref(j_query);
            if (res == H_OK && json_array_size(j_result_scope) > 0) {
              if (!json_object_set_new(json_array_get(j_result, 0), "scope", json_array())) {
                json_array_foreach(j_result_scope, index, j_element) {
                  if (scope_list == NULL) {
                    scope_list = o_strdup(json_string_value(json_object_get(j_element, "name")));
                  } else {
                    tmp = msprintf("%s %s", scope_list, json_string_value(json_object_get(j_element, "name")));
                    o_free(scope_list);
                    scope_list = tmp;
                  }
                  if ((j_scope_param = get_scope_parameters(config, json_string_value(json_object_get(j_element, "name")))) != NULL) {
                    json_object_update(j_element, j_scope_param);
                    json_decref(j_scope_param);
                  }
                  if (json_object_get(j_element, "refresh-token-rolling") != NULL && rolling_refresh_override != 0) {
                    rolling_refresh_override = json_object_get(j_element, "refresh-token-rolling")==json_true();
                  }
                  if (json_integer_value(json_object_get(j_element, "refresh-token-duration")) && (json_integer_value(json_object_get(j_element, "refresh-token-duration")) < maximum_duration_override || maximum_duration_override == -1)) {
                    maximum_duration_override = json_integer_value(json_object_get(j_element, "refresh-token-duration"));
                  }
                  json_array_append(json_object_get(json_array_get(j_result, 0), "scope"), j_element);
                }
                if (rolling_refresh_override > -1) {
                  rolling_refresh = rolling_refresh_override;
                }
                if (maximum_duration_override > -1) {
                  maximum_duration = maximum_duration_override;
                }
                json_object_set_new(json_array_get(j_result, 0), "scope_list", json_string(scope_list));
                json_object_set_new(json_array_get(j_result, 0), "refresh-token-rolling", rolling_refresh?json_true():json_false());
                json_object_set_new(json_array_get(j_result, 0), "refresh-token-duration", json_integer(maximum_duration));
                j_return = json_pack("{sisO}", "result", G_OK, "code", json_array_get(j_result, 0));
                o_free(scope_list);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "validate_authorization_code - oauth2 - Error allocating resources for json_array()");
                j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "validate_authorization_code - oauth2 - Error executing j_query (2)");
              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
              j_return = json_pack("{si}", "result", G_ERROR_DB);
            }
            json_decref(j_result_scope);
          } else if (res == G_ERROR_UNAUTHORIZED) {
            j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          } else if (res == G_ERROR_PARAM) {
            j_return = json_pack("{si}", "result", G_ERROR_PARAM);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "validate_authorization_code - oauth2 - Error validate_code_challenge");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
        } else {
          if (json_true() == json_object_get(config->j_params, "auth-type-code-revoke-replayed")) {
            if (revoke_tokens_from_code(config, json_integer_value(json_object_get(json_array_get(j_result, 0), "gpgc_id")), ip_source) != G_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "validate_authorization_code - oauth2 - Error revoke_tokens_from_code");
            }
          }
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "validate_authorization_code - oauth2 - Error executing j_query (1)");
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "validate_authorization_code - oauth2 - Error glewlwyd_callback_generate_hash");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  o_free(code_hash);
  return j_return;
}

static json_t * validate_session_client_scope(struct _oauth2_config * config, const struct _u_request * request, const char * client_id, const char * scope) {
  json_t * j_session, * j_grant, * j_return, * j_scope_session, * j_scope_grant = NULL, * j_group = NULL, * j_scheme;
  const char * scope_session, * group = NULL;
  char * scope_filtered = NULL, * tmp;
  size_t index = 0;
  json_int_t scopes_authorized = 0, scopes_granted = 0, group_allowed;

  j_session = config->glewlwyd_config->glewlwyd_callback_check_session_valid(config->glewlwyd_config, request, scope);
  if (check_result_value(j_session, G_OK)) {
    j_grant = config->glewlwyd_config->glewlwyd_callback_get_client_granted_scopes(config->glewlwyd_config, client_id, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), scope);
    if (check_result_value(j_grant, G_OK)) {
      if (json_array_size(json_object_get(json_object_get(j_grant, "grant"), "scope"))) {
        // Count and store the number of granted scopes
        json_array_foreach(json_object_get(json_object_get(j_grant, "grant"), "scope"), index, j_scope_grant) {
          scopes_granted += json_object_get(j_scope_grant, "granted")==json_true();
        }
        json_object_set_new(json_object_get(j_session, "session"), "scopes_granted", json_integer(scopes_granted));

        json_object_foreach(json_object_get(json_object_get(j_session, "session"), "scope"), scope_session, j_scope_session) {
          // Evaluate if the scope is granted for the client
          json_array_foreach(json_object_get(json_object_get(j_grant, "grant"), "scope"), index, j_scope_grant) {
            if (0 == o_strcmp(scope_session, json_string_value(json_object_get(j_scope_grant, "name")))) {
              json_object_set(j_scope_session, "granted", json_object_get(j_scope_grant, "granted"));
            }
          }

          // Evaluate if the scope is authorized
          if (json_object_get(j_scope_session, "available") == json_true()) {
            if (json_object_get(j_scope_session, "password_required") == json_true() && json_object_get(j_scope_session, "password_authenticated") == json_false()) {
              json_object_set_new(j_scope_session, "authorized", json_false());
            } else if ((json_object_get(j_scope_session, "password_required") == json_true() && json_object_get(j_scope_session, "password_authenticated") == json_true()) || json_object_get(j_scope_session, "password_required") == json_false()) {
              json_object_foreach(json_object_get(j_scope_session, "schemes"), group, j_group) {
                group_allowed = 0;
                json_array_foreach(j_group, index, j_scheme) {
                  if (json_object_get(j_scheme, "scheme_authenticated") == json_true()) {
                    group_allowed++;
                  }
                }
                if (group_allowed < json_integer_value(json_object_get(json_object_get(j_scope_session, "scheme_required"), group))) {
                  json_object_set_new(j_scope_session, "authorized", json_false());
                }
              }
              if (json_object_get(j_scope_session, "authorized") == NULL) {
                json_object_set_new(j_scope_session, "authorized", json_true());
                scopes_authorized++;
                if (json_object_get(j_scope_session, "granted") == json_true()) {
                  if (scope_filtered == NULL) {
                    scope_filtered = o_strdup(scope_session);
                  } else {
                    tmp = msprintf("%s %s", scope_filtered, scope_session);
                    o_free(scope_filtered);
                    scope_filtered = tmp;
                  }
                }
              } else if (json_object_get(j_scope_session, "granted") == json_true()) {
                json_object_set_new(json_object_get(j_session, "session"), "authorization_required", json_true());
              }
            } else {
              json_object_set_new(j_scope_session, "authorized", json_false());
            }
          } else {
            json_object_set_new(j_scope_session, "authorized", json_false());
          }
        }
        json_object_set_new(json_object_get(j_session, "session"), "scopes_authorized", json_integer(scopes_authorized));
        if (json_object_get(json_object_get(j_session, "session"), "authorization_required") == NULL) {
          json_object_set_new(json_object_get(j_session, "session"), "authorization_required", json_false());
        }
        if (scope_filtered != NULL) {
          json_object_set_new(json_object_get(j_session, "session"), "scope_filtered", json_string(scope_filtered));
          o_free(scope_filtered);
        } else {
          json_object_set_new(json_object_get(j_session, "session"), "scope_filtered", json_string(""));
          json_object_set_new(json_object_get(j_session, "session"), "authorization_required", json_true());
        }
        if (scopes_authorized && scopes_granted) {
          j_return = json_pack("{sisO}", "result", G_OK, "session", json_object_get(j_session, "session"));
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_client_scope - oauth2 - Error glewlwyd_callback_get_client_granted_scopes");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_grant);
  } else if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "validate_session_client_scope - oauth2 - Error glewlwyd_callback_check_session_valid");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_session);
  return j_return;
}

static json_t * validate_refresh_token(struct _oauth2_config * config, const char * refresh_token) {
  json_t * j_return, * j_query, * j_result, * j_result_scope, * j_element = NULL;
  char * token_hash, * expires_at_clause;
  int res;
  size_t index = 0;
  time_t now;

  if (refresh_token != NULL) {
    token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, refresh_token);
    if (token_hash != NULL) {
      time(&now);
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("> %u", (now));
      }
      j_query = json_pack("{sss[sssssssss]s{sssssis{ssss}}}",
                          "table",
                          GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                          "columns",
                            "gpgr_id",
                            "gpgc_id",
                            "gpgr_username AS username",
                            "gpgr_client_id AS client_id",
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_issued_at) AS issued_at", "gpgr_issued_at AS issued_at", "EXTRACT(EPOCH FROM gpgr_issued_at)::integer AS issued_at"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_expires_at) AS expired_at", "gpgr_expires_at AS expired_at", "EXTRACT(EPOCH FROM gpgr_expires_at)::integer AS expired_at"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_last_seen) AS last_seen", "gpgr_last_seen AS last_seen", "EXTRACT(EPOCH FROM gpgr_last_seen)::integer AS last_seen"),
                            "gpgr_duration AS duration",
                            "gpgr_rolling_expiration",
                          "where",
                            "gpgr_plugin_name",
                            config->name,
                            "gpgr_token_hash",
                            token_hash,
                            "gpgr_enabled",
                            1,
                            "gpgr_expires_at",
                              "operator",
                              "raw",
                              "value",
                              expires_at_clause);
      o_free(expires_at_clause);
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result) > 0) {
          json_object_set(json_array_get(j_result, 0), "rolling_expiration", json_integer_value(json_object_get(json_array_get(j_result, 0), "gpgr_rolling_expiration"))?json_true():json_false());
          json_object_del(json_array_get(j_result, 0), "gpgr_rolling_expiration");
          j_query = json_pack("{sss[s]s{sO}}",
                              "table",
                              GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN_SCOPE,
                              "columns",
                                "gpgrs_scope AS scope",
                              "where",
                                "gpgr_id",
                                json_object_get(json_array_get(j_result, 0), "gpgr_id"));
          res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result_scope, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            if (!json_object_set_new(json_array_get(j_result, 0), "scope", json_array())) {
              json_array_foreach(j_result_scope, index, j_element) {
                json_array_append(json_object_get(json_array_get(j_result, 0), "scope"), json_object_get(j_element, "scope"));
              }
              j_return = json_pack("{sisO}", "result", G_OK, "token", json_array_get(j_result, 0));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "validate_refresh_token - oauth2 - Error json_object_set_new");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            json_decref(j_result_scope);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "validate_refresh_token - oauth2 - Error executing j_query (2)");
            config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "validate_refresh_token - oauth2 - Error executing j_query (1)");
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "validate_refresh_token - oauth2 - Error glewlwyd_callback_generate_hash");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(token_hash);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

static json_t * refresh_token_list_get(struct _oauth2_config * config, const char * username, const char * pattern, size_t offset, size_t limit, const char * sort) {
  json_t * j_query, * j_result, * j_return, * j_element = NULL;
  int res;
  size_t index = 0, token_hash_dec_len = 0;
  char * pattern_escaped, * pattern_clause, * name_escaped;
  unsigned char token_hash_dec[128];

  j_query = json_pack("{sss[ssssssssss]s{ssss}sisiss}",
                      "table",
                      GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                      "columns",
                        "gpgr_token_hash",
                        "gpgr_authorization_type",
                        "gpgr_client_id AS client_id",
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_issued_at) AS issued_at", "gpgr_issued_at AS issued_at", "EXTRACT(EPOCH FROM gpgr_issued_at)::integer AS issued_at"),
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_expires_at) AS expires_at", "gpgr_expires_at AS expires_at", "EXTRACT(EPOCH FROM gpgr_expires_at)::integer AS expires_at"),
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_last_seen) AS last_seen", "gpgr_last_seen AS last_seen", "EXTRACT(EPOCH FROM gpgr_last_seen)::integer AS last_seen"),
                        "gpgr_rolling_expiration",
                        "gpgr_issued_for AS issued_for",
                        "gpgr_user_agent AS user_agent",
                        "gpgr_enabled",
                      "where",
                        "gpgr_plugin_name",
                        config->name,
                        "gpgr_username",
                        username,
                      "offset",
                      offset,
                      "limit",
                      limit,
                      "order_by",
                      "gpgr_last_seen DESC");
  if (sort != NULL) {
    json_object_set_new(j_query, "order_by", json_string(sort));
  }
  if (pattern != NULL) {
    pattern_escaped = h_escape_string_with_quotes(config->glewlwyd_config->glewlwyd_config->conn, pattern);
    name_escaped = h_escape_string_with_quotes(config->glewlwyd_config->glewlwyd_config->conn, config->name);
    pattern_clause = msprintf("IN (SELECT gpgr_id FROM "GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN" WHERE (gpgr_user_agent LIKE '%%'||%s||'%%' OR gpgr_issued_for LIKE '%%'||%s||'%%') AND gpgr_plugin_name=%s)", pattern_escaped, pattern_escaped, name_escaped);
    json_object_set_new(json_object_get(j_query, "where"), "gpgr_id", json_pack("{ssss}", "operator", "raw", "value", pattern_clause));
    o_free(pattern_clause);
    o_free(pattern_escaped);
    o_free(name_escaped);
  }
  res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      json_object_set(j_element, "rolling_expiration", (json_integer_value(json_object_get(j_element, "gpgr_rolling_expiration"))?json_true():json_false()));
      json_object_set(j_element, "enabled", (json_integer_value(json_object_get(j_element, "gpgr_enabled"))?json_true():json_false()));
      json_object_del(j_element, "gpgr_rolling_expiration");
      json_object_del(j_element, "gpgr_enabled");
      if (o_base64_2_base64url((unsigned char *)json_string_value(json_object_get(j_element, "gpgr_token_hash")), json_string_length(json_object_get(j_element, "gpgr_token_hash")), token_hash_dec, &token_hash_dec_len)) {
        json_object_set_new(j_element, "token_hash", json_stringn((char *)token_hash_dec, token_hash_dec_len));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_list_get - Error o_base64_2_base64url");
        json_object_set_new(j_element, "token_hash", json_string("error"));
      }
      json_object_del(j_element, "gpgr_token_hash");
      switch(json_integer_value(json_object_get(j_element, "gpgr_authorization_type"))) {
        case GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE:
          json_object_set_new(j_element, "authorization_type", json_string("code"));
          break;
        case GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS:
          json_object_set_new(j_element, "authorization_type", json_string("password"));
          break;
        default:
          json_object_set_new(j_element, "authorization_type", json_string("unknown"));
          break;
      }
      json_object_del(j_element, "gpgr_authorization_type");
    }
    j_return = json_pack("{sisO}", "result", G_OK, "refresh_token", j_result);
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_list_get - Error executing j_query");
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static int refresh_token_disable(struct _oauth2_config * config, const char * username, const char * token_hash, const char * ip_source) {
  json_t * j_query, * j_result, * j_element = NULL;
  int res, ret = G_OK;
  unsigned char token_hash_dec[128];
  size_t token_hash_dec_len = 0, index = 0;

  j_query = json_pack("{sss[ss]s{ssss}}",
                      "table",
                      GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                      "columns",
                        "gpgr_id",
                        "gpgr_enabled",
                      "where",
                        "gpgr_plugin_name", config->name,
                        "gpgr_username", username);
  if (token_hash != NULL) {
    if (o_base64url_2_base64((unsigned char *)token_hash, o_strlen(token_hash), token_hash_dec, &token_hash_dec_len)) {
      json_object_set_new(json_object_get(j_query, "where"), "gpgr_token_hash", json_stringn((const char *)token_hash_dec, token_hash_dec_len));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "update_refresh_token - oauth2 - Error o_base64url_2_base64");
      ret = G_ERROR_PARAM;
    }
  }
  res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK && ret == G_OK) {
    if (json_array_size(j_result)) {
      json_array_foreach(j_result, index, j_element) {
        if (json_integer_value(json_object_get(j_element, "gpgr_enabled"))) {
          j_query = json_pack("{sss{si}s{sssO}}",
                              "table",
                              GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                              "set",
                                "gpgr_enabled", 0,
                              "where",
                                "gpgr_plugin_name", config->name,
                                "gpgr_id", json_object_get(j_element, "gpgr_id"));
          res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            if (token_hash != NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "update_refresh_token - oauth2 - token '[...%s]' disabled, origin: %s", token_hash + (o_strlen(token_hash) - (o_strlen(token_hash)>=8?8:o_strlen(token_hash))), ip_source);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "update_refresh_token - oauth2 - Error executing j_query (2)");
            config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
            ret = G_ERROR_DB;
          }
        } else if (token_hash != NULL) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "update_refresh_token - oauth2 - Error token '[...%s]' already disabled, origin: %s", token_hash + (o_strlen(token_hash) - (o_strlen(token_hash)>=8?8:o_strlen(token_hash))), ip_source);
          ret = G_ERROR_PARAM;
        }
      }
    } else if (token_hash != NULL) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "update_refresh_token - oauth2 - Error token '[...%s]' not found, origin: %s", token_hash + (o_strlen(token_hash) - (o_strlen(token_hash)>=8?8:o_strlen(token_hash))), ip_source);
      ret = G_ERROR_NOT_FOUND;
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "update_refresh_token - oauth2 - Error executing j_query (1)");
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    ret = G_ERROR_DB;
  }
  return ret;
}

static int update_refresh_token(struct _oauth2_config * config, json_int_t gpgr_id, json_int_t refresh_token_duration, int disable, time_t now) {
  json_t * j_query;
  int res, ret;
  char * expires_at_clause, * last_seen_clause;

  if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
    last_seen_clause = msprintf("FROM_UNIXTIME(%u)", (now));
  } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
    last_seen_clause = msprintf("TO_TIMESTAMP(%u)", now);
  } else { // HOEL_DB_TYPE_SQLITE
    last_seen_clause = msprintf("%u", (now));
  }
  j_query = json_pack("{sss{s{ss}}s{sssI}}",
                      "table",
                      GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                      "set",
                        "gpgr_last_seen",
                          "raw",
                          last_seen_clause,
                      "where",
                        "gpgr_plugin_name",
                        config->name,
                        "gpgr_id",
                        gpgr_id);
  o_free(last_seen_clause);
  if (refresh_token_duration) {
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (time_t)refresh_token_duration));
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (time_t)refresh_token_duration));
    } else { // HOEL_DB_TYPE_SQLITE
      expires_at_clause = msprintf("%u", (now + (time_t)refresh_token_duration));
    }
    json_object_set_new(json_object_get(j_query, "set"), "gpgr_expires_at", json_pack("{ss}", "raw", expires_at_clause));
    o_free(expires_at_clause);
  }
  if (disable) {
    json_object_set_new(json_object_get(j_query, "set"), "gpgr_enabled", json_integer(0));
  }
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "update_refresh_token - oauth2 - Error executing j_query");
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    ret = G_ERROR_DB;
  }
  return ret;
}

static json_t * get_refresh_token_duration_rolling(struct _oauth2_config * config, const char * scope_list) {
  json_t * j_return, * j_element = NULL;
  char ** scope_array = NULL;
  size_t i, index = 0;
  json_int_t maximum_duration = config->refresh_token_duration, maximum_duration_override = -1;
  int rolling_refresh = config->refresh_token_rolling, rolling_refresh_override = -1;

  if (split_string_remove_duplicates(scope_list, " ", &scope_array)) {
    json_array_foreach(json_object_get(config->j_params, "scope"), index, j_element) {
      for (i=0; scope_array[i]!=NULL; i++) {
        if (0 == o_strcmp(json_string_value(json_object_get(j_element, "name")), scope_array[i])) {
          if (json_integer_value(json_object_get(j_element, "refresh-token-duration")) && (json_integer_value(json_object_get(j_element, "refresh-token-duration")) < maximum_duration_override || maximum_duration_override == -1)) {
            maximum_duration_override = json_integer_value(json_object_get(j_element, "refresh-token-duration"));
          }
          if (json_object_get(j_element, "refresh-token-rolling") != NULL && rolling_refresh_override != 0) {
            rolling_refresh_override = json_object_get(j_element, "refresh-token-rolling")==json_true();
          }
        }
      }
    }
    free_string_array(scope_array);
    if (maximum_duration_override != -1) {
      maximum_duration = maximum_duration_override;
    }
    if (rolling_refresh_override != -1) {
      rolling_refresh = rolling_refresh_override;
    }
    j_return = json_pack("{sis{sosI}}", "result", G_OK, "refresh-token", "refresh-token-rolling", rolling_refresh?json_true():json_false(), "refresh-token-duration", maximum_duration);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_refresh_token_duration_rolling - Error split_string_remove_duplicates");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  return j_return;
}

static int is_code_challenge_valid(struct _oauth2_config * config, const char * code_challenge, const char * code_challenge_method, char * code_challenge_stored) {
  int ret;
  if (!o_strnullempty(code_challenge)) {
    if (json_object_get(config->j_params, "pkce-allowed") == json_true()) {
      if (o_strnullempty(code_challenge_method) || 0 == o_strcmp("plain", code_challenge_method)) {
        if (json_object_get(config->j_params, "pkce-method-plain-allowed") == json_true()) {
          if (is_pkce_char_valid(code_challenge)) {
            o_strcpy(code_challenge_stored, code_challenge);
            ret = G_OK;
          } else {
            ret = G_ERROR_PARAM;
          }
        } else {
          ret = G_ERROR_PARAM;
        }
      } else if (0 == o_strcmp("S256", code_challenge_method)) {
        if (o_strlen(code_challenge) == 43) {
          o_strcpy(code_challenge_stored, GLEWLWYD_CODE_CHALLENGE_S256_PREFIX);
          o_strcpy(code_challenge_stored + o_strlen(GLEWLWYD_CODE_CHALLENGE_S256_PREFIX), code_challenge);
          ret = G_OK;
        } else {
          ret = G_ERROR_PARAM;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
    } else {
      ret = G_ERROR_PARAM;
    }
  } else {
    // No pkce
    ret = G_OK;
  }
  return ret;
}

static int revoke_refresh_token(struct _oauth2_config * config, const char * token) {
  json_t * j_query;
  int res, ret;
  char * token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token);

  j_query = json_pack("{sss{si}s{ssss}}",
                      "table",
                      GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                      "set",
                        "gpgr_enabled",
                        0,
                      "where",
                        "gpgr_plugin_name",
                        config->name,
                        "gpgr_token_hash",
                        token_hash);
  o_free(token_hash);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "revoke_refresh_token - Error executing j_query");
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    ret = G_ERROR_DB;
  }
  return ret;
}

static int revoke_access_token(struct _oauth2_config * config, const char * token) {
  json_t * j_query;
  int res, ret;
  char * token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token);

  j_query = json_pack("{sss{si}s{ssss}}",
                      "table",
                      GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN,
                      "set",
                        "gpga_enabled",
                        0,
                      "where",
                        "gpga_plugin_name",
                        config->name,
                        "gpga_token_hash",
                        token_hash);
  o_free(token_hash);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "revoke_access_token - Error executing j_query");
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
    ret = G_ERROR_DB;
  }
  return ret;
}

static json_t * get_token_metadata(struct _oauth2_config * config, const char * token, const char * token_type_hint, const char * client_id) {
  json_t * j_query, * j_result, * j_result_scope, * j_return = NULL, * j_element = NULL;
  int res, found_refresh = 0, found_access = 0;
  size_t index = 0;
  char * token_hash = NULL, * scope_list = NULL, * expires_at_clause;
  time_t now;

  if (!o_strnullempty(token)) {
    token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token);
    time(&now);
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
    } else { // HOEL_DB_TYPE_SQLITE
      expires_at_clause = msprintf("> %u", (now));
    }
    if (token_type_hint == NULL || 0 == o_strcmp("refresh_token", token_type_hint)) {
      j_query = json_pack("{sss[sssssss]s{sssss{ssss}}}",
                          "table",
                          GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                          "columns",
                            "gpgr_id",
                            "gpgr_username AS username",
                            "gpgr_client_id AS client_id",
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_issued_at) AS iat", "gpgr_issued_at AS iat", "EXTRACT(EPOCH FROM gpgr_issued_at)::integer AS iat"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_issued_at) AS nbf", "gpgr_issued_at AS nbf", "EXTRACT(EPOCH FROM gpgr_issued_at)::integer AS nbf"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_expires_at) AS exp", "gpgr_expires_at AS exp", "EXTRACT(EPOCH FROM gpgr_expires_at)::integer AS exp"),
                            "gpgr_enabled",
                          "where",
                            "gpgr_plugin_name",
                            config->name,
                            "gpgr_token_hash",
                            token_hash,
                            "gpgr_expires_at",
                              "operator",
                              "raw",
                              "value",
                              expires_at_clause);
      if (client_id != NULL) {
        json_object_set_new(json_object_get(j_query, "where"), "gpgr_client_id", json_string(client_id));
      }
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          found_refresh = 1;
          if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gpgr_enabled"))) {
            json_object_set_new(json_array_get(j_result, 0), "active", json_true());
            json_object_set_new(json_array_get(j_result, 0), "token_type", json_string("refresh_token"));
            json_object_del(json_array_get(j_result, 0), "gpgr_enabled");
            if (json_object_get(json_array_get(j_result, 0), "client_id") == json_null()) {
              json_object_del(json_array_get(j_result, 0), "client_id");
            }
            if (json_object_get(json_array_get(j_result, 0), "username") == json_null()) {
              json_object_del(json_array_get(j_result, 0), "username");
            }
            j_query = json_pack("{sss[s]s{sO}}",
                                "table",
                                GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN_SCOPE,
                                "columns",
                                  "gpgrs_scope AS scope",
                                "where",
                                  "gpgr_id",
                                  json_object_get(json_array_get(j_result, 0), "gpgr_id"));
            res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result_scope, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              json_array_foreach(j_result_scope, index, j_element) {
                if (scope_list == NULL) {
                  scope_list = o_strdup(json_string_value(json_object_get(j_element, "scope")));
                } else {
                  scope_list = mstrcatf(scope_list, " %s", json_string_value(json_object_get(j_element, "scope")));
                }
              }
              json_object_set_new(json_array_get(j_result, 0), "scope", json_string(scope_list));
              o_free(scope_list);
              json_decref(j_result_scope);
              json_object_del(json_array_get(j_result, 0), "gpgr_id");
              j_return = json_pack("{sisO}", "result", G_OK, "token", json_array_get(j_result, 0));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "validate_refresh_token - oauth2 - Error executing j_query scope refresh_token");
              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
              j_return = json_pack("{si}", "result", G_ERROR_DB);
            }
          } else {
            j_return = json_pack("{sis{so}}", "result", G_OK, "token", "active", json_false());
          }
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_token_metadata - Error executing j_query refresh_token");
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    }
    if ((token_type_hint == NULL && !found_refresh) || 0 == o_strcmp("access_token", token_type_hint)) {
      j_query = json_pack("{sss[ssssss]s{ssss}}",
                          "table",
                          GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN,
                          "columns",
                            "gpga_id",
                            "gpga_username AS username",
                            "gpga_client_id AS client_id",
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpga_issued_at) AS iat", "gpga_issued_at AS iat", "EXTRACT(EPOCH FROM gpga_issued_at)::integer AS iat"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpga_issued_at) AS nbf", "gpga_issued_at AS nbf", "EXTRACT(EPOCH FROM gpga_issued_at)::integer AS nbf"),
                            "gpga_enabled",
                          "where",
                            "gpga_plugin_name",
                            config->name,
                            "gpga_token_hash",
                            token_hash);
      if (client_id != NULL) {
        json_object_set_new(json_object_get(j_query, "where"), "gpga_client_id", json_string(client_id));
      }
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          found_access = 1;
          if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gpga_enabled")) && json_integer_value(json_object_get(json_array_get(j_result, 0), "iat")) + json_integer_value(json_object_get(config->j_params, "access-token-duration")) > (json_int_t)now) {
            json_object_set_new(json_array_get(j_result, 0), "active", json_true());
            json_object_set_new(json_array_get(j_result, 0), "token_type", json_string("access_token"));
            json_object_set_new(json_array_get(j_result, 0), "exp", json_integer(json_integer_value(json_object_get(json_array_get(j_result, 0), "iat")) + json_integer_value(json_object_get(config->j_params, "access-token-duration"))));
            json_object_del(json_array_get(j_result, 0), "gpga_enabled");
            if (json_object_get(json_array_get(j_result, 0), "client_id") == json_null()) {
              json_object_del(json_array_get(j_result, 0), "client_id");
            }
            if (json_object_get(json_array_get(j_result, 0), "username") == json_null()) {
              json_object_del(json_array_get(j_result, 0), "username");
            }
            j_query = json_pack("{sss[s]s{sO}}",
                                "table",
                                GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN_SCOPE,
                                "columns",
                                  "gpgas_scope AS scope",
                                "where",
                                  "gpga_id",
                                  json_object_get(json_array_get(j_result, 0), "gpga_id"));
            res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result_scope, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              json_array_foreach(j_result_scope, index, j_element) {
                if (scope_list == NULL) {
                  scope_list = o_strdup(json_string_value(json_object_get(j_element, "scope")));
                } else {
                  scope_list = mstrcatf(scope_list, " %s", json_string_value(json_object_get(j_element, "scope")));
                }
              }
              json_object_set_new(json_array_get(j_result, 0), "scope", json_string(scope_list));
              o_free(scope_list);
              json_decref(j_result_scope);
              json_object_del(json_array_get(j_result, 0), "gpga_id");
              j_return = json_pack("{sisO}", "result", G_OK, "token", json_array_get(j_result, 0));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 validate_refresh_token - Error executing j_query scope access_token");
              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
              j_return = json_pack("{si}", "result", G_ERROR_DB);
            }
          } else {
            j_return = json_pack("{sis{so}}", "result", G_OK, "token", "active", json_false());
          }
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_token_metadata - Error executing j_query access_token");
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    }
    if (!found_refresh && !found_access && j_return == NULL) {
      j_return = json_pack("{sis{so}}", "result", G_OK, "token", "active", json_false());
    }
    o_free(token_hash);
    o_free(expires_at_clause);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

static const char * get_client_id_for_introspection(struct _oauth2_config * config, const struct _u_request * request) {
  if (u_map_get_case(request->map_header, HEADER_AUTHORIZATION) != NULL && config->introspect_revoke_resource_config->oauth_scope != NULL) {
    return NULL;
  } else if (json_object_get(config->j_params, "introspection-revocation-allow-target-client") == json_true()) {
    return request->auth_basic_user;
  } else {
    return NULL;
  }
}

static json_t * generate_device_authorization(struct _oauth2_config * config, const char * client_id, const char * scope_list, const char * ip_source) {
  char device_code[GLEWLWYD_DEVICE_AUTH_DEVICE_CODE_LENGTH+1] = {0}, user_code[GLEWLWYD_DEVICE_AUTH_USER_CODE_LENGTH+2] = {0}, * device_code_hash = NULL, * user_code_hash = NULL;
  json_t * j_return, * j_query, * j_device_auth_id;
  int res;
  time_t now, expiration = (time_t)json_integer_value(json_object_get(config->j_params, "device-authorization-expiration"));
  char * expires_at_clause = NULL, * last_check_clause = NULL, ** scope_array = NULL;
  size_t i;

  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_device_authorization oauth2 - Error pthread_mutex_lock");
    j_return = json_pack("{si}", "result", G_ERROR);
  } else {
    if (rand_string(device_code, 32) != NULL && rand_string_from_charset(user_code, GLEWLWYD_DEVICE_AUTH_USER_CODE_LENGTH+1, "ABCDEFGHJKLMNOPQRSTUVWXYZ0123456789") != NULL) {
      user_code[4] = '-';
      device_code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, device_code);
      user_code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, user_code);
      time(&now);
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + expiration));
        last_check_clause = msprintf("FROM_UNIXTIME(%u)", (now - (2*expiration)));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + expiration));
        last_check_clause = msprintf("TO_TIMESTAMP(%u)", (now - (2*expiration)));
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("%u", (now + expiration));
        last_check_clause = msprintf("%u", (now - (2*expiration)));
      }
      j_query = json_pack("{sss{sssss{ss}sssssss{ss}}}",
                          "table",
                          GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION,
                          "values",
                            "gpgda_plugin_name",
                            config->name,
                            "gpgda_client_id",
                            client_id,
                            "gpgda_expires_at",
                              "raw",
                              expires_at_clause,
                            "gpgda_issued_for",
                            ip_source,
                            "gpgda_device_code_hash",
                            device_code_hash,
                            "gpgda_user_code_hash",
                            user_code_hash,
                            "gpgda_last_check",
                              "raw",
                              last_check_clause);
      o_free(expires_at_clause);
      o_free(last_check_clause);
      o_free(device_code_hash);
      o_free(user_code_hash);
      res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        j_device_auth_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
        if (j_device_auth_id != NULL) {
          if (split_string_remove_duplicates(scope_list, " ", &scope_array)) {
            j_query = json_pack("{sss[]}", "table", GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION_SCOPE, "values");
            for (i=0; scope_array[i]!=NULL; i++) {
              json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOss}", "gpgda_id", j_device_auth_id, "gpgdas_scope", scope_array[i]));
            }
            res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
            json_decref(j_query);
            if (res == H_OK) {
              j_return = json_pack("{sis{ssss}}", "result", G_OK, "authorization", "device_code", device_code, "user_code", user_code);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "generate_device_authorization - Error executing j_query (2)");
              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
              j_return = json_pack("{si}", "result", G_ERROR_DB);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_device_authorization - Error split_string_remove_duplicates scope");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          free_string_array(scope_array);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_device_authorization - Error h_last_insert_id");
          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        json_decref(j_device_auth_id);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_device_authorization - Error executing j_query (1)");
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_device_authorization - Error generating random code");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    pthread_mutex_unlock(&config->insert_lock);
  }
  return j_return;
}

static int validate_device_authorization_scope(struct _oauth2_config * config, json_int_t gpgda_id, const char * username, const char * scope_list) {
  char * query, * scope_clause = NULL, * scope_escaped, ** scope_array = NULL, * username_escaped;
  int res, i, ret;

  if (split_string_remove_duplicates(scope_list, " ", &scope_array)) {
    for (i=0; scope_array[i]!=NULL; i++) {
      scope_escaped = h_escape_string_with_quotes(config->glewlwyd_config->glewlwyd_config->conn, scope_array[i]);
      if (scope_clause == NULL) {
        scope_clause = o_strdup(scope_escaped);
      } else {
        scope_clause = mstrcatf(scope_clause, ",%s", scope_escaped);
      }
      o_free(scope_escaped);
    }
    free_string_array(scope_array);
  }
  if (!o_strnullempty(scope_clause)) {
    query = msprintf("UPDATE %s set gpgdas_allowed=1 WHERE gpgdas_scope IN (%s) AND gpgda_id=%"JSON_INTEGER_FORMAT, GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION_SCOPE, scope_clause, gpgda_id);
    res = h_execute_query(config->glewlwyd_config->glewlwyd_config->conn, query, NULL, H_OPTION_EXEC);
    o_free(query);
    if (res == H_OK) {
      username_escaped = h_escape_string_with_quotes(config->glewlwyd_config->glewlwyd_config->conn, username);
      query = msprintf("UPDATE %s set gpgda_status=1, gpgda_username=%s WHERE gpgda_id=%"JSON_INTEGER_FORMAT, GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION, username_escaped, gpgda_id);
      res = h_execute_query(config->glewlwyd_config->glewlwyd_config->conn, query, NULL, H_OPTION_EXEC);
      o_free(username_escaped);
      o_free(query);
      if (res == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "validate_device_authorization_scope - Error executing query (2)");
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
        ret = G_ERROR_DB;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "validate_device_authorization_scope - Error executing query (1)");
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
      ret = G_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "validate_device_authorization_scope - Error scope invalid");
    ret = G_ERROR_PARAM;
  }
  o_free(scope_clause);
  return ret;
}

static json_t * validate_device_auth_user_code(struct _oauth2_config * config, const char * user_code) {
  json_t * j_query = NULL, * j_result = NULL, * j_result_scope = NULL, * j_return, * j_element = NULL;
  int res;
  char * scope = NULL, * expires_at_clause, * user_code_hash, user_code_ucase[GLEWLWYD_DEVICE_AUTH_USER_CODE_LENGTH+2] = {0};
  time_t now;
  size_t index = 0;

  if (o_strlen(user_code) == GLEWLWYD_DEVICE_AUTH_USER_CODE_LENGTH+1 && user_code[4] == '-') {
    for (index=0; index<(GLEWLWYD_DEVICE_AUTH_USER_CODE_LENGTH+1); index++) {
      user_code_ucase[index] = (char)toupper(user_code[index]);
    }
    user_code_ucase[GLEWLWYD_DEVICE_AUTH_USER_CODE_LENGTH+1] = '\0';
    time(&now);
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expires_at_clause = msprintf("> TO_TIMESTAMP(%u)", now);
    } else { // HOEL_DB_TYPE_SQLITE
      expires_at_clause = msprintf("> %u", (now));
    }
    user_code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, user_code_ucase);
    j_query = json_pack("{sss[ss]s{sss{ssss}sssi}}",
                        "table",
                        GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION,
                        "columns",
                          "gpgda_id",
                          "gpgda_client_id",
                        "where",
                          "gpgda_plugin_name",
                          config->name,
                          "gpgda_expires_at",
                            "operator",
                            "raw",
                            "value",
                            expires_at_clause,
                          "gpgda_user_code_hash",
                          user_code_hash,
                          "gpgda_status",
                          0);
    o_free(expires_at_clause);
    o_free(user_code_hash);
    res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        j_query = json_pack("{sss[s]s{sO}}",
                            "table",
                            GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION_SCOPE,
                            "columns",
                              "gpgdas_scope",
                            "where",
                              "gpgda_id",
                              json_object_get(json_array_get(j_result, 0), "gpgda_id"));
        res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result_scope, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          json_array_foreach(j_result_scope, index, j_element) {
            if (scope == NULL) {
              scope = o_strdup(json_string_value(json_object_get(j_element, "gpgdas_scope")));
            } else {
              scope = mstrcatf(scope, " %s", json_string_value(json_object_get(j_element, "gpgdas_scope")));
            }
          }
          j_return = json_pack("{sis{sOsssO}}", "result", G_OK, "device_auth", "client_id", json_object_get(json_array_get(j_result, 0), "gpgda_client_id"), "scope", scope, "gpgda_id", json_object_get(json_array_get(j_result, 0), "gpgda_id"));
          o_free(scope);
          json_decref(j_result_scope);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "validate_device_auth_user_code - Error executing j_query (2)");
          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "validate_device_auth_user_code - Error executing j_query (1)");
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_DATABSE_ERROR, 1, NULL);
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

static int check_auth_type_device_code(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  json_t * j_body, * j_client, * j_query, * j_result = NULL, * j_result_scope = NULL, * j_element = NULL, * j_user = NULL, * j_refresh_token = NULL, * j_user_only = NULL;
  const char * device_code = u_map_get(request->map_post_body, "device_code"),
             * client_id = request->auth_basic_user,
             * client_secret = request->auth_basic_password,
             * ip_source = get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header),
             * username = NULL;
  int res;
  char * device_code_hash, * refresh_token, * access_token, * scope = NULL, * issued_for = get_client_hostname(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
  time_t now;
  size_t index = 0;

  if (client_id == NULL && u_map_get(request->map_post_body, "client_id") != NULL) {
    client_id = u_map_get(request->map_post_body, "client_id");
  }
  if (client_secret == NULL && u_map_get(request->map_post_body, "client_secret") != NULL) {
    client_secret = u_map_get(request->map_post_body, "client_secret");
  }
  if (o_strlen(device_code) == GLEWLWYD_DEVICE_AUTH_DEVICE_CODE_LENGTH) {
    j_client = check_client_valid(config, client_id, client_id, client_secret, NULL, GLEWLWYD_AUTHORIZATION_TYPE_DEVICE_AUTHORIZATION, 0, ip_source);
    if (check_result_value(j_client, G_OK)) {
      device_code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, device_code);
      j_query = json_pack("{sss[sssss]s{sssOs{ssss}}}",
                          "table",
                          GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION,
                          "columns",
                            "gpgda_id",
                            "gpgda_username AS username",
                            "gpgda_status",
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgda_expires_at) AS expires_at", "gpgda_expires_at AS expires_at", "EXTRACT(EPOCH FROM gpgda_expires_at)::integer AS expires_at"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgda_last_check) AS last_check", "gpgda_last_check AS last_check", "EXTRACT(EPOCH FROM gpgda_last_check)::integer AS last_check"),
                          "where",
                            "gpgda_device_code_hash",
                            device_code_hash,
                            "gpgda_client_id",
                            json_object_get(json_object_get(j_client, "client"), "client_id"),
                            "gpgda_status",
                              "operator",
                              "raw",
                              "value",
                              "<= 1");
      o_free(device_code_hash);
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          time(&now);
          if (json_integer_value(json_object_get(json_array_get(j_result, 0), "expires_at")) >= (json_int_t)now) {
            if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gpgda_status")) == 1) {
              j_query = json_pack("{sss[s]s{sOsi}}",
                                  "table",
                                  GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION_SCOPE,
                                  "columns",
                                    "gpgdas_scope",
                                  "where",
                                    "gpgda_id",
                                    json_object_get(json_array_get(j_result, 0), "gpgda_id"),
                                    "gpgdas_allowed",
                                    1);
              res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result_scope, NULL);
              json_decref(j_query);
              if (res == H_OK) {
                json_array_foreach(j_result_scope, index, j_element) {
                  if (scope == NULL) {
                    scope = o_strdup(json_string_value(json_object_get(j_element, "gpgdas_scope")));
                  } else {
                    scope = mstrcatf(scope, " %s", json_string_value(json_object_get(j_element, "gpgdas_scope")));
                  }
                }
                // All clear, please send back tokens
                username = json_string_value(json_object_get(json_array_get(j_result, 0), "username"));
                j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, username);
                if (check_result_value(j_user, G_OK)) {
                  time(&now);
                  if ((refresh_token = generate_refresh_token(config, client_id, username, json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")), now, ip_source)) != NULL) {
                    j_refresh_token = serialize_refresh_token(config, GLEWLWYD_AUTHORIZATION_TYPE_DEVICE_AUTHORIZATION, 0, username, client_id, scope, now, config->refresh_token_duration, config->refresh_token_rolling, refresh_token, issued_for, u_map_get_case(request->map_header, "user-agent"));
                    if (check_result_value(j_refresh_token, G_OK)) {
                      j_user_only = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, username);
                      if (check_result_value(j_user_only, G_OK)) {
                        if ((access_token = generate_access_token(config,
                                                                  username,
                                                                  client_id,
                                                                  json_object_get(j_user_only, "user"),
                                                                  json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")),
                                                                  now,
                                                                  ip_source)) != NULL) {
                          if (serialize_access_token(config, GLEWLWYD_AUTHORIZATION_TYPE_DEVICE_AUTHORIZATION, json_integer_value(json_object_get(j_refresh_token, "gpgr_id")), username, client_id, scope, now, issued_for, u_map_get_case(request->map_header, "user-agent"), access_token) == G_OK) {
                            j_query = json_pack("{sss{si}s{sO}}",
                                                "table",
                                                GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION,
                                                "set",
                                                  "gpgda_status", 2,
                                                "where",
                                                  "gpgda_id", json_object_get(json_array_get(j_result, 0), "gpgda_id"));
                            res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
                            json_decref(j_query);
                            if (res == H_OK) {
                              j_body = json_pack("{sssssssisIss}",
                                                 "token_type",
                                                 "bearer",
                                                 "access_token",
                                                 access_token,
                                                 "refresh_token",
                                                 refresh_token,
                                                 "iat",
                                                 now,
                                                 "expires_in",
                                                 config->access_token_duration,
                                                 "scope",
                                                 scope);
                              ulfius_set_json_body_response(response, 200, j_body);
                              json_decref(j_body);
                              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 1, "plugin", config->name, "response_type", "device_code", NULL);
                              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 1, "plugin", config->name, NULL);
                              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, "response_type", "device_code", NULL);
                              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, NULL);
                            } else {
                              y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_device_code - oauth2 - Error executing j_query (4)");
                              j_body = json_pack("{ss}", "error", "server_error");
                              ulfius_set_json_body_response(response, 500, j_body);
                              json_decref(j_body);
                            }
                          } else {
                            y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_device_code - oauth2 - Error serialize_access_token");
                            j_body = json_pack("{ss}", "error", "server_error");
                            ulfius_set_json_body_response(response, 500, j_body);
                            json_decref(j_body);
                          }
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_device_code - oauth2 - Error generate_access_token");
                          j_body = json_pack("{ss}", "error", "server_error");
                          ulfius_set_json_body_response(response, 500, j_body);
                          json_decref(j_body);
                        }
                        o_free(access_token);
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_device_code - oauth2 - Error glewlwyd_plugin_callback_get_user");
                        j_body = json_pack("{ss}", "error", "server_error");
                        ulfius_set_json_body_response(response, 500, j_body);
                        json_decref(j_body);
                      }
                      json_decref(j_user_only);
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_device_code - oauth2 - Error serialize_refresh_token");
                      j_body = json_pack("{ss}", "error", "server_error");
                      ulfius_set_json_body_response(response, 500, j_body);
                      json_decref(j_body);
                    }
                    json_decref(j_refresh_token);
                    o_free(refresh_token);
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_device_code - oauth2 - Error generate_refresh_token");
                    j_body = json_pack("{ss}", "error", "server_error");
                    ulfius_set_json_body_response(response, 500, j_body);
                    json_decref(j_body);
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_device_code - oauth2 - Error getting user %s", username);
                  j_body = json_pack("{ss}", "error", "server_error");
                  ulfius_set_json_body_response(response, 500, j_body);
                  json_decref(j_body);
                }
                json_decref(j_user);
                o_free(scope);
                json_decref(j_result_scope);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_device_code - Error executing j_query (2)");
                j_body = json_pack("{ss}", "error", "server_error");
                ulfius_set_json_body_response(response, 500, j_body);
                json_decref(j_body);
              }
            } else {
              j_query = json_pack("{sss{s{ss}}s{sO}}",
                                  "table",
                                  GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION,
                                  "set",
                                    "gpgda_last_check",
                                      "raw",
                                      SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "CURRENT_TIMESTAMP", "strftime('%s','now')", "NOW()"),
                                  "where",
                                    "gpgda_id",
                                    json_object_get(json_array_get(j_result, 0), "gpgda_id"));
              res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
              json_decref(j_query);
              if (res == H_OK) {
                if (((json_int_t)now - json_integer_value(json_object_get(json_array_get(j_result, 0), "last_check"))) >= json_integer_value(json_object_get(config->j_params, "device-authorization-interval"))) {
                  // Wait for it!
                  j_body = json_pack("{ss}", "error", "authorization_pending");
                  ulfius_set_json_body_response(response, 400, j_body);
                  json_decref(j_body);
                } else {
                  // Slow down dammit!
                  j_body = json_pack("{ss}", "error", "slow_down");
                  ulfius_set_json_body_response(response, 400, j_body);
                  json_decref(j_body);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_device_code - Error executing j_query (3)");
                j_body = json_pack("{ss}", "error", "server_error");
                ulfius_set_json_body_response(response, 500, j_body);
                json_decref(j_body);
              }
            }
          } else {
            // Code expired
            j_body = json_pack("{ss}", "error", "expired_token");
            ulfius_set_json_body_response(response, 400, j_body);
            json_decref(j_body);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "check_auth_type_device_code - Invalid code");
          j_body = json_pack("{ss}", "error", "access_denied");
          ulfius_set_json_body_response(response, 400, j_body);
          json_decref(j_body);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_device_code - Error executing j_query (1)");
        j_body = json_pack("{ss}", "error", "server_error");
        ulfius_set_json_body_response(response, 500, j_body);
        json_decref(j_body);
      }
    } else {
      j_body = json_pack("{ss}", "error", "unauthorized_client");
      ulfius_set_json_body_response(response, 403, j_body);
      json_decref(j_body);
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_UNAUTHORIZED_CLIENT, 1, "plugin", config->name, NULL);
    }
    json_decref(j_client);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "check_auth_type_device_code - Missing code");
    j_body = json_pack("{ss}", "error", "access_denied");
    ulfius_set_json_body_response(response, 400, j_body);
    json_decref(j_body);
  }
  o_free(issued_for);
  return U_CALLBACK_CONTINUE;
}

static int callback_revocation(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  json_t * j_result = get_token_metadata(config, u_map_get(request->map_post_body, "token"), u_map_get(request->map_post_body, "token_type_hint"), get_client_id_for_introspection(config, request));

  if (check_result_value(j_result, G_OK)) {
    if (json_object_get(json_object_get(j_result, "token"), "active") == json_true()) {
      if (0 == o_strcmp("refresh_token", json_string_value(json_object_get(json_object_get(j_result, "token"), "token_type")))) {
        if (revoke_refresh_token(config, u_map_get(request->map_post_body, "token")) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_revocation  - Error revoke_refresh_token");
          response->status = 500;
        } else {
          y_log_message(Y_LOG_LEVEL_INFO, "Event oauth2 - Plugin '%s' - Refresh token generated for client '%s' revoked, origin: %s", config->name, json_string_value(json_object_get(json_object_get(j_result, "token"), "client_id")), get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
        }
      } else {
        if (revoke_access_token(config, u_map_get(request->map_post_body, "token")) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_revocation  - Error revoke_access_token");
          response->status = 500;
        } else {
          y_log_message(Y_LOG_LEVEL_INFO, "Event oauth2 - Plugin '%s' - Access token generated for client '%s' revoked, origin: %s", config->name, json_string_value(json_object_get(json_object_get(j_result, "token"), "client_id")), get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
        }
      }
    }
  } else if (check_result_value(j_result, G_ERROR_PARAM)) {
    response->status = 400;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_introspection - Error get_token_metadata");
    response->status = 500;
  }
  json_decref(j_result);
  return U_CALLBACK_CONTINUE;
}

static int callback_introspection(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  json_t * j_result = get_token_metadata(config, u_map_get(request->map_post_body, "token"), u_map_get(request->map_post_body, "token_type_hint"), get_client_id_for_introspection(config, request));

  if (check_result_value(j_result, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_result, "token"));
  } else if (check_result_value(j_result, G_ERROR_PARAM)) {
    response->status = 400;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_introspection - Error get_token_metadata");
    response->status = 500;
  }
  json_decref(j_result);
  return U_CALLBACK_CONTINUE;
}

static int callback_check_intropect_revoke(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  json_t * j_client, * j_element = NULL, * j_introspect;
  size_t index = 0;
  int ret = U_CALLBACK_UNAUTHORIZED;

  if (u_map_get_case(request->map_header, HEADER_AUTHORIZATION) != NULL && config->introspect_revoke_resource_config->oauth_scope != NULL) {
    j_introspect = get_token_metadata(config, (u_map_get_case(request->map_header, HEADER_AUTHORIZATION) + o_strlen(HEADER_PREFIX_BEARER)), "access_token", NULL);
    if (check_result_value(j_introspect, G_OK) && json_object_get(json_object_get(j_introspect, "token"), "active") == json_true()) {
      ret = callback_check_glewlwyd_access_token(request, response, (void*)config->introspect_revoke_resource_config);
    }
    json_decref(j_introspect);
  } else if (json_object_get(config->j_params, "introspection-revocation-allow-target-client") == json_true()) {
    j_client = config->glewlwyd_config->glewlwyd_callback_check_client_valid(config->glewlwyd_config, request->auth_basic_user, request->auth_basic_password);
    if (check_result_value(j_client, G_OK) && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
      json_array_foreach(json_object_get(json_object_get(j_client, "client"), "authorization_type"), index, j_element) {
        if (0 == o_strcmp(json_string_value(j_element), "client_credentials")) {
          ret = U_CALLBACK_CONTINUE;
        }
      }
    }
    json_decref(j_client);
  }
  return ret;
}

/**
 * The most used authorization type: if client is authorized and has been granted access to scope,
 * glewlwyd redirects to redirect_uri with a code in the uri
 * If necessary, an intermediate step can be used: login page
 */
static int check_auth_type_auth_code_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  char * authorization_code = NULL, * redirect_url, * issued_for, * state_param = NULL, * state_encoded, code_challenge_stored[GLEWLWYD_CODE_CHALLENGE_MAX_LENGTH + 1] = {0};
  const char * ip_source = get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
  json_t * j_session, * j_client = check_client_valid(config, u_map_get(request->map_url, "client_id"), request->auth_basic_user, request->auth_basic_password, u_map_get(request->map_url, "redirect_uri"), GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, 1, ip_source);
  int res;

  if (u_map_get(request->map_url, "state") != NULL) {
    state_encoded = ulfius_url_encode(u_map_get(request->map_url, "state"));
    state_param = msprintf("&state=%s", state_encoded);
    o_free(state_encoded);
  } else {
    state_param = o_strdup("");
  }
  // Check if client is allowed to perform this request
  if (check_result_value(j_client, G_OK)) {
    // Client is allowed to use auth_code grant with this redirection_uri
    if (u_map_has_key(request->map_url, "g_continue")) {
      if (!o_strnullempty(u_map_get(request->map_url, "scope"))) {
        j_session = validate_session_client_scope(config, request, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
        if (check_result_value(j_session, G_OK)) {
          if (json_object_get(json_object_get(j_session, "session"), "authorization_required") == json_false()) {
            // User has granted access to the cleaned scope list for this client
            // Generate code, generate the url and redirect to it
            issued_for = get_client_hostname(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
            if (issued_for != NULL) {
              if (config->glewlwyd_config->glewlwyd_callback_trigger_session_used(config->glewlwyd_config, request, json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered"))) == G_OK) {
                if ((res = is_code_challenge_valid(config, u_map_get(request->map_url, "code_challenge"), u_map_get(request->map_url, "code_challenge_method"), code_challenge_stored)) == G_OK) {
                  if ((authorization_code = generate_authorization_code(config, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered")), u_map_get(request->map_url, "redirect_uri"), issued_for, u_map_get_case(request->map_header, "user-agent"), code_challenge_stored)) != NULL) {
                    redirect_url = msprintf("%s%scode=%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), authorization_code, state_param);
                    ulfius_add_header_to_response(response, "Location", redirect_url);
                    response->status = 302;
                    o_free(redirect_url);
                    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_CODE, 1, "plugin", config->name, NULL);
                  } else {
                    redirect_url = msprintf("%s%serror=server_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
                    ulfius_add_header_to_response(response, "Location", redirect_url);
                    o_free(redirect_url);
                    y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_auth_code_grant - oauth2 - Error generate_authorization_code");
                    response->status = 302;
                  }
                  o_free(authorization_code);
                } else if (res == G_ERROR_PARAM) {
                  redirect_url = msprintf("%s%serror=invalid_request", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
                  ulfius_add_header_to_response(response, "Location", redirect_url);
                  o_free(redirect_url);
                  y_log_message(Y_LOG_LEVEL_DEBUG, "check_auth_type_auth_code_grant - oauth2 - Invalid code_challenge or code_challenge_method, origin: %s", get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
                  response->status = 302;
                } else {
                  redirect_url = msprintf("%s%serror=server_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
                  ulfius_add_header_to_response(response, "Location", redirect_url);
                  o_free(redirect_url);
                  y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_auth_code_grant - oauth2 - Error is_code_challenge_valid");
                  response->status = 302;
                }
              } else {
                redirect_url = msprintf("%s%serror=server_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
                y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_auth_code_grant - oauth2 - Error glewlwyd_callback_trigger_session_used");
                response->status = 302;
              }
            } else {
              redirect_url = msprintf("%s%serror=server_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_auth_code_grant - oauth2 - Error get_client_hostname");
              response->status = 302;
            }
            o_free(issued_for);
          } else {
            // Redirect to login page
            redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"), NULL);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
            response->status = 302;
          }
        } else if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
          // Redirect to login page
          redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"), NULL);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          response->status = 302;
        } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
          // Scope is not allowed for this user
          response->status = 302;
          y_log_message(Y_LOG_LEVEL_DEBUG, "check_auth_type_auth_code_grant - oauth2 - scope list '%s' is invalid for user '%s', origin: %s", u_map_get(request->map_url, "scope"), json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), ip_source);
          redirect_url = msprintf("%s%serror=invalid_scope%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        } else {
          redirect_url = msprintf("%s%serror=server_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_auth_code_grant - oauth2 - Error validate_session_client_scope");
          response->status = 302;
        }
        json_decref(j_session);
      } else {
        // Scope is not allowed for this user
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_auth_type_auth_code_grant - oauth2 - scope list is missing or empty, origin: %s", ip_source);
        response->status = 302;
        redirect_url = msprintf("%s%serror=invalid_scope%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), state_param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
    } else {
      // Redirect to login page
      redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"), NULL);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      response->status = 302;
    }
  } else {
    // client is not authorized
    response->status = 302;
    redirect_url = msprintf("%s%serror=unauthorized_client%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
    ulfius_add_header_to_response(response, "Location", redirect_url);
    o_free(redirect_url);
    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_UNAUTHORIZED_CLIENT, 1, "plugin", config->name, NULL);
  }
  o_free(state_param);
  json_decref(j_client);
  return U_CALLBACK_CONTINUE;
}

/**
 * The second step of authentiation code
 * Validates if code, client_id and redirect_uri sent are valid, then returns a token set
 */
static int check_auth_type_access_token_request (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  const char * code = u_map_get(request->map_post_body, "code"),
             * client_id = u_map_get(request->map_post_body, "client_id"),
             * redirect_uri = u_map_get(request->map_post_body, "redirect_uri"),
             * code_verifier = u_map_get(request->map_post_body, "code_verifier"),
             * ip_source = get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
  char * issued_for = get_client_hostname(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
  json_t * j_code, * j_body, * j_refresh_token, * j_client, * j_user;
  time_t now;
  char * refresh_token = NULL, * access_token = NULL;

  if (client_id == NULL && request->auth_basic_user != NULL) {
    client_id = request->auth_basic_user;
  }
  if (code == NULL || client_id == NULL || redirect_uri == NULL) {
    response->status = 400;
  } else {
    j_client = check_client_valid(config, client_id, request->auth_basic_user, request->auth_basic_password, redirect_uri, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, 0, ip_source);
    if (check_result_value(j_client, G_OK)) {
      j_code = validate_authorization_code(config, code, client_id, redirect_uri, code_verifier, ip_source);
      if (check_result_value(j_code, G_OK)) {
        j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, json_string_value(json_object_get(json_object_get(j_code, "code"), "username")));
        if (check_result_value(j_user, G_OK)) {
          time(&now);
          if ((refresh_token = generate_refresh_token(config, client_id, json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), now, ip_source)) != NULL) {
            j_refresh_token = serialize_refresh_token(config, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, json_integer_value(json_object_get(json_object_get(j_code, "code"), "gpgc_id")), json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), client_id, json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), now, json_integer_value(json_object_get(json_object_get(j_code, "code"), "refresh-token-duration")), json_object_get(json_object_get(j_code, "code"), "refresh-token-rolling")==json_true(), refresh_token, issued_for, u_map_get_case(request->map_header, "user-agent"));
            if (check_result_value(j_refresh_token, G_OK)) {
              if ((access_token = generate_access_token(config,
                                                        json_string_value(json_object_get(json_object_get(j_code, "code"), "username")),
                                                        client_id,
                                                        json_object_get(j_user, "user"),
                                                        json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")),
                                                        now,
                                                        ip_source)) != NULL) {
                if (serialize_access_token(config, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, json_integer_value(json_object_get(j_refresh_token, "gpgr_id")), json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), client_id, json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), now, issued_for, u_map_get_case(request->map_header, "user-agent"), access_token) == G_OK) {
                  if (disable_authorization_code(config, json_integer_value(json_object_get(json_object_get(j_code, "code"), "gpgc_id"))) == G_OK) {
                    j_body = json_pack("{sssssssisIss}",
                                          "token_type",
                                          "bearer",
                                          "access_token",
                                          access_token,
                                          "refresh_token",
                                          refresh_token,
                                          "iat",
                                          now,
                                          "expires_in",
                                          config->access_token_duration,
                                          "scope",
                                          json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")));
                    ulfius_set_json_body_response(response, 200, j_body);
                    json_decref(j_body);
                    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 1, "plugin", config->name, "response_type", "code", NULL);
                    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 1, "plugin", config->name, NULL);
                    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, "response_type", "code", NULL);
                    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, NULL);
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - oauth2 - Error disable_authorization_code");
                    j_body = json_pack("{ss}", "error", "server_error");
                    ulfius_set_json_body_response(response, 500, j_body);
                    json_decref(j_body);
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - oauth2 - Error serialize_access_token");
                  j_body = json_pack("{ss}", "error", "server_error");
                  ulfius_set_json_body_response(response, 500, j_body);
                  json_decref(j_body);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - oauth2 - Error generate_access_token");
                j_body = json_pack("{ss}", "error", "server_error");
                ulfius_set_json_body_response(response, 500, j_body);
                json_decref(j_body);
              }
              o_free(access_token);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - oauth2 - Error serialize_refresh_token");
              j_body = json_pack("{ss}", "error", "server_error");
              ulfius_set_json_body_response(response, 500, j_body);
              json_decref(j_body);
            }
            json_decref(j_refresh_token);
            o_free(refresh_token);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - oauth2 - Error generate_refresh_token");
            j_body = json_pack("{ss}", "error", "server_error");
            ulfius_set_json_body_response(response, 500, j_body);
            json_decref(j_body);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_access_token_request - oauth2 - Error glewlwyd_plugin_callback_get_user");
          j_body = json_pack("{ss}", "error", "server_error");
          ulfius_set_json_body_response(response, 500, j_body);
          json_decref(j_body);
        }
        json_decref(j_user);
      } else if (check_result_value(j_code, G_ERROR_UNAUTHORIZED)) {
        y_log_message(Y_LOG_LEVEL_WARNING, "Security - Code invalid at IP Address %s", get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
        j_body = json_pack("{ss}", "error", "invalid_code");
        ulfius_set_json_body_response(response, 403, j_body);
        json_decref(j_body);
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_INVALID_CODE, 1, "plugin", config->name, NULL);
      } else if (check_result_value(j_code, G_ERROR_PARAM)) {
        y_log_message(Y_LOG_LEVEL_WARNING, "Security - Code invalid at IP Address %s", get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
        j_body = json_pack("{ss}", "error", "invalid_request");
        ulfius_set_json_body_response(response, 403, j_body);
        json_decref(j_body);
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_INVALID_CODE, 1, "plugin", config->name, NULL);
      } else {
        j_body = json_pack("{ss}", "error", "server_error");
        ulfius_set_json_body_response(response, 500, j_body);
        json_decref(j_body);
      }
      json_decref(j_code);
    } else {
      j_body = json_pack("{ss}", "error", "unauthorized_client");
      ulfius_set_json_body_response(response, 403, j_body);
      json_decref(j_body);
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_UNAUTHORIZED_CLIENT, 1, "plugin", config->name, NULL);
    }
    json_decref(j_client);
  }
  o_free(issued_for);
  return U_CALLBACK_CONTINUE;
}

/**
 * The second more simple authorization type: client redirects user to login page,
 * Then if authorized, glewlwyd redirects to redirect_uri with the access_token in the uri
 * If necessary, an intermediate step can be used: login page
 */
static int check_auth_type_implicit_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  const char * ip_source = get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
  char * redirect_url, * issued_for, * state_encoded = NULL, * state_param = NULL;
  json_t * j_session,
         * j_client = check_client_valid(config, u_map_get(request->map_url, "client_id"), request->auth_basic_user, request->auth_basic_password, u_map_get(request->map_url, "redirect_uri"), GLEWLWYD_AUTHORIZATION_TYPE_IMPLICIT, 1, ip_source);
  char * access_token;
  time_t now;

  if (u_map_get(request->map_url, "state") != NULL) {
    state_encoded = ulfius_url_encode(u_map_get(request->map_url, "state"));
    state_param = msprintf("&state=%s", state_encoded);
    o_free(state_encoded);
  } else {
    state_param = o_strdup("");
  }
  // Check if client is allowed to perform this request
  if (check_result_value(j_client, G_OK)) {
    // Client is allowed to use auth_code grant with this redirection_uri
    if (u_map_has_key(request->map_url, "g_continue")) {
      if (!o_strnullempty(u_map_get(request->map_url, "scope"))) {
        j_session = validate_session_client_scope(config, request, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
        if (check_result_value(j_session, G_OK)) {
          if (json_object_get(json_object_get(j_session, "session"), "authorization_required") == json_false()) {
            // User has granted access to the cleaned scope list for this client
            // Generate access token
            issued_for = get_client_hostname(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
            if (issued_for != NULL) {
              time(&now);
              if ((access_token = generate_access_token(config,
                                                        json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")),
                                                        u_map_get(request->map_url, "client_id"),
                                                        json_object_get(json_object_get(j_session, "session"), "user"),
                                                        json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered")),
                                                        now,
                                                        ip_source)) != NULL) {
                if (serialize_access_token(config, GLEWLWYD_AUTHORIZATION_TYPE_IMPLICIT, 0, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered")), now, issued_for, u_map_get_case(request->map_header, "user-agent"), access_token) == G_OK) {
                  if (config->glewlwyd_config->glewlwyd_callback_trigger_session_used(config->glewlwyd_config, request, json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered"))) == G_OK) {
                    redirect_url = msprintf("%s%saccess_token=%s&token_type=bearer&expires_in=%" JSON_INTEGER_FORMAT "&scope=%s%s",
                                            u_map_get(request->map_url, "redirect_uri"),
                                            (o_strchr(u_map_get(request->map_url, "redirect_uri"), '#')!=NULL?"&":"#"),
                                            access_token,
                                            config->access_token_duration,
                                            json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered")),
                                            state_param);
                    ulfius_add_header_to_response(response, "Location", redirect_url);
                    o_free(redirect_url);
                    response->status = 302;
                    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, "response_type", "code", NULL);
                    config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, NULL);
                  } else {
                    redirect_url = msprintf("%s%serror=server_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
                    ulfius_add_header_to_response(response, "Location", redirect_url);
                    o_free(redirect_url);
                    y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_implicit_grant - oauth2 - Error glewlwyd_callback_trigger_session_used");
                    response->status = 302;
                  }
                } else {
                  redirect_url = msprintf("%s%serror=server_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
                  ulfius_add_header_to_response(response, "Location", redirect_url);
                  o_free(redirect_url);
                  y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_implicit_grant - oauth2 - Error serialize_access_token");
                  response->status = 302;
                }
              } else {
                redirect_url = msprintf("%s%serror=server_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
                y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_implicit_grant - oauth2 - Error generate_access_token");
                response->status = 302;
              }
              o_free(access_token);
            } else {
              redirect_url = msprintf("%s%serror=server_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_implicit_grant - oauth2 - Error get_client_hostname");
              response->status = 302;
            }
            o_free(issued_for);
          } else {
            // Redirect to login page
            redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"), NULL);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
            response->status = 302;
          }
        } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
          // Scope is not allowed for this user
          y_log_message(Y_LOG_LEVEL_DEBUG, "check_auth_type_implicit_grant - oauth2 - Scope list '%s' is not allowed for user '%s', origin: %s", u_map_get(request->map_url, "scope"), json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), ip_source);
          response->status = 302;
          redirect_url = msprintf("%s%serror=invalid_scope%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        } else {
          redirect_url = msprintf("%s%serror=server_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_implicit_grant - oauth2 - Error validate_session_client_scope");
          response->status = 302;
        }
        json_decref(j_session);
      } else {
        // Empty scope is not allowed
        response->status = 302;
        redirect_url = msprintf("%s%serror=invalid_scope%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), state_param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
    } else {
      // Redirect to login page
      redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"), NULL);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      response->status = 302;
    }
  } else {
    // client is not authorized
    response->status = 302;
    redirect_url = msprintf("%s%serror=unauthorized_client%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
    ulfius_add_header_to_response(response, "Location", redirect_url);
    o_free(redirect_url);
  }
  o_free(state_param);
  json_decref(j_client);
  return U_CALLBACK_CONTINUE;
}

/**
 * The more simple authorization type
 * username and password are given in the POST parameters,
 * the access_token and refresh_token in a json object are returned
 */
static int check_auth_type_resource_owner_pwd_cred (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  json_t * j_user, * j_client, * j_refresh_token, * j_body, * j_user_only, * j_element = NULL, * j_refresh = NULL;
  int ret = G_OK, auth_type_allowed = 0;
  const char * username = u_map_get(request->map_post_body, "username"),
             * password = u_map_get(request->map_post_body, "password"),
             * scope = u_map_get(request->map_post_body, "scope"),
             * client_id = NULL,
             * ip_source = get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
  char * issued_for = get_client_hostname(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header),
       * refresh_token,
       * access_token;
  time_t now;
  size_t index = 0;

  if (scope == NULL || username == NULL || password == NULL || issued_for == NULL) {
    ret = G_ERROR_PARAM;
  } else if (request->auth_basic_user != NULL && request->auth_basic_password != NULL) {
    j_client = config->glewlwyd_config->glewlwyd_callback_check_client_valid(config->glewlwyd_config, request->auth_basic_user, request->auth_basic_password);
    if (check_result_value(j_client, G_OK) && json_object_get(json_object_get(j_client, "client"), "confidential") != json_true()) {
      ret = G_ERROR_PARAM;
    } else if (check_result_value(j_client, G_OK)) {
      json_array_foreach(json_object_get(json_object_get(j_client, "client"), "authorization_type"), index, j_element) {
        if (0 == o_strcmp(json_string_value(j_element), "password")) {
          auth_type_allowed = 1;
        }
      }
      if (!auth_type_allowed) {
        ret = G_ERROR_PARAM;
      } else {
        client_id = request->auth_basic_user;
      }
    } else if (check_result_value(j_client, G_ERROR_NOT_FOUND) || check_result_value(j_client, G_ERROR_UNAUTHORIZED)) {
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - oauth2 - Error glewlwyd_callback_check_client_valid");
      ret = G_ERROR;
    }
    json_decref(j_client);
  }
  if (ret == G_OK) {
    j_user = config->glewlwyd_config->glewlwyd_callback_check_user_valid(config->glewlwyd_config, username, password, scope);
    if (check_result_value(j_user, G_OK)) {
      j_refresh = get_refresh_token_duration_rolling(config, json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")));
      if (check_result_value(j_refresh, G_OK)) {
        time(&now);
        if ((refresh_token = generate_refresh_token(config,
                                                    client_id,
                                                    username,
                                                    json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")),
                                                    now,
                                                    ip_source)) != NULL) {
          j_refresh_token = serialize_refresh_token(config,
                                                    GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS,
                                                    0,
                                                    username,
                                                    client_id,
                                                    json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")),
                                                    now,
                                                    json_integer_value(json_object_get(json_object_get(j_refresh, "refresh-token"), "refresh-token-duration")),
                                                    json_object_get(json_object_get(j_refresh, "refresh-token"), "refresh-token-rolling")==json_true(),
                                                    refresh_token,
                                                    issued_for,
                                                    u_map_get_case(request->map_header, "user-agent"));
          if (check_result_value(j_refresh_token, G_OK)) {
            j_user_only = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, username);
            if (check_result_value(j_user_only, G_OK)) {
              if ((access_token = generate_access_token(config,
                                                        username,
                                                        client_id,
                                                        json_object_get(j_user_only, "user"),
                                                        json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")),
                                                        now,
                                                        ip_source)) != NULL) {
                if (serialize_access_token(config,
                                           GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS,
                                           json_integer_value(json_object_get(j_refresh_token, "gpgr_id")),
                                           username,
                                           client_id,
                                           json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")),
                                           now,
                                           issued_for,
                                           u_map_get_case(request->map_header, "user-agent"),
                                           access_token) == G_OK) {
                  j_body = json_pack("{sssssssisIss}",
                                     "token_type",
                                     "bearer",
                                     "access_token",
                                     access_token,
                                     "refresh_token",
                                     refresh_token,
                                     "iat",
                                     now,
                                     "expires_in",
                                     config->access_token_duration,
                                     "scope",
                                     json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")));
                  ulfius_set_json_body_response(response, 200, j_body);
                  json_decref(j_body);
                  config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 1, "plugin", config->name, "response_type", "password", NULL);
                  config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 1, "plugin", config->name, NULL);
                  config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, "response_type", "password", NULL);
                  config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, NULL);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - oauth2 - Error serialize_access_token");
                  j_body = json_pack("{ss}", "error", "server_error");
                  ulfius_set_json_body_response(response, 500, j_body);
                  json_decref(j_body);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - oauth2 - Error generate_access_token");
                j_body = json_pack("{ss}", "error", "server_error");
                ulfius_set_json_body_response(response, 500, j_body);
                json_decref(j_body);
              }
              o_free(access_token);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - oauth2 - Error glewlwyd_plugin_callback_get_user");
              j_body = json_pack("{ss}", "error", "server_error");
              ulfius_set_json_body_response(response, 500, j_body);
              json_decref(j_body);
            }
            json_decref(j_user_only);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - oauth2 - Error serialize_refresh_token");
            j_body = json_pack("{ss}", "error", "server_error");
            ulfius_set_json_body_response(response, 500, j_body);
            json_decref(j_body);
          }
          json_decref(j_refresh_token);
          o_free(refresh_token);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - oauth2 - Error generate_refresh_token");
          j_body = json_pack("{ss}", "error", "server_error");
          ulfius_set_json_body_response(response, 500, j_body);
          json_decref(j_body);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - oauth2 - Error get_refresh_token_duration_rolling");
        j_body = json_pack("{ss}", "error", "server_error");
        ulfius_set_json_body_response(response, 500, j_body);
        json_decref(j_body);
      }
      json_decref(j_refresh);
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND) || check_result_value(j_user, G_ERROR_UNAUTHORIZED)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "check_auth_type_resource_owner_pwd_cred - oauth2 - Error user '%s'", username);
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Authorization invalid for username %s at IP Address %s", username, ip_source);
      response->status = 403;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_resource_owner_pwd_cred - oauth2 - glewlwyd_callback_check_user_valid");
      response->status = 403;
    }
    json_decref(j_user);
  } else if (ret == G_ERROR_PARAM) {
    response->status = 400;
  } else {
    response->status = 500;
  }
  o_free(issued_for);
  return U_CALLBACK_CONTINUE;
}

/**
 * Send an access_token to a confidential client
 */
static int check_auth_type_client_credentials_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  json_t * j_client, * j_element = NULL, * json_body;
  char ** scope_array, ** scope_allowed = NULL, * scope_joined, * access_token, * issued_for = get_client_hostname(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
  size_t index = 0;
  int i, i_scope_allowed = 0, auth_type_allowed = 0;
  time_t now;
  const char * ip_source = get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);

  if (issued_for == NULL) {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_client_credentials_grant - oauth2  - Error get_client_hostname");
    response->status = 500;
  } else if (request->auth_basic_user != NULL && request->auth_basic_password != NULL && !o_strnullempty(u_map_get(request->map_post_body, "scope"))) {
    j_client = config->glewlwyd_config->glewlwyd_callback_check_client_valid(config->glewlwyd_config, request->auth_basic_user, request->auth_basic_password);
    if (check_result_value(j_client, G_OK) && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
      json_array_foreach(json_object_get(json_object_get(j_client, "client"), "authorization_type"), index, j_element) {
        if (0 == o_strcmp(json_string_value(j_element), "client_credentials")) {
          auth_type_allowed = 1;
        }
      }
      if (split_string_remove_duplicates(u_map_get(request->map_post_body, "scope"), " ", &scope_array) > 0) {
        for (i=0; scope_array[i]!=NULL; i++) {
          json_array_foreach(json_object_get(json_object_get(j_client, "client"), "scope"), index, j_element) {
            if (0 == o_strcmp(json_string_value(j_element), scope_array[i])) {
              if (scope_allowed == NULL) {
                scope_allowed = o_malloc(2 * sizeof(char*));
              } else {
                scope_allowed = o_realloc(scope_allowed, (2 + (size_t)i_scope_allowed) * sizeof(char*));
              }
              scope_allowed[i_scope_allowed] = scope_array[i];
              scope_allowed[i_scope_allowed+1] = NULL;
              i_scope_allowed++;
            }
          }
        }
        if (!i_scope_allowed) {
          json_body = json_pack("{ss}", "error", "scope_invalid");
          ulfius_set_json_body_response(response, 400, json_body);
          json_decref(json_body);
        } else if (!auth_type_allowed) {
          json_body = json_pack("{ss}", "error", "authorization_type_invalid");
          ulfius_set_json_body_response(response, 400, json_body);
          json_decref(json_body);
        } else {
          scope_joined = string_array_join((const char **)scope_allowed, " ");
          time(&now);
          if ((access_token = generate_client_access_token(config, request->auth_basic_user, scope_joined, json_object_get(j_client, "client"), now, ip_source)) != NULL) {
            if (serialize_access_token(config, GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS, 0, NULL, request->auth_basic_user, scope_joined, now, issued_for, u_map_get_case(request->map_header, "user-agent"), access_token) == G_OK) {
              json_body = json_pack("{sssssIss}",
                                    "access_token", access_token,
                                    "token_type", "bearer",
                                    "expires_in", config->access_token_duration,
                                    "scope", scope_joined);
              ulfius_set_json_body_response(response, 200, json_body);
              json_decref(json_body);
              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_CLIENT_ACCESS_TOKEN, 1, "plugin", config->name, NULL);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_client_credentials_grant - oauth2 - Error serialize_access_token");
              response->status = 500;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_client_credentials_grant - oauth2 - Error generate_client_access_token");
            response->status = 500;
          }
          o_free(access_token);
          o_free(scope_joined);
          o_free(scope_allowed);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_client_credentials_grant - oauth2 - Error split_string_remove_duplicates");
        response->status = 500;
      }
      free_string_array(scope_array);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_auth_type_client_credentials_grant - Error client_id '%s' invalid", request->auth_basic_user);
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Authorization invalid for client_id %s at IP Address %s", request->auth_basic_user, ip_source);
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_UNAUTHORIZED_CLIENT, 1, "plugin", config->name, NULL);
      response->status = 403;
    }
    json_decref(j_client);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_auth_type_client_credentials_grant - Error invalid input parameters. client_id: '%s', scope: '%s', origin: %s", request->auth_basic_user, u_map_get(request->map_post_body, "scope"), get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
    response->status = 403;
  }
  o_free(issued_for);
  return U_CALLBACK_CONTINUE;
}

/**
 * Get a new access_token from a valid refresh_token
 */
static int get_access_token_from_refresh (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  const char * refresh_token = u_map_get(request->map_post_body, "refresh_token"), * ip_source = get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
  json_t * j_refresh, * json_body, * j_client, * j_user;
  time_t now;
  char * access_token, * scope_joined = NULL, * issued_for;
  int has_error = 0, has_issues = 0;

  if (refresh_token != NULL && !o_strnullempty(refresh_token)) {
    j_refresh = validate_refresh_token(config, refresh_token);
    if (check_result_value(j_refresh, G_OK)) {
      if (json_object_get(json_object_get(j_refresh, "token"), "client_id") != json_null()) {
        j_client = check_client_valid(config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), request->auth_basic_user, request->auth_basic_password, NULL, GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN, 0, ip_source);
        if (!check_result_value(j_client, G_OK)) {
          has_issues = 1;
        } else if (request->auth_basic_user == NULL && request->auth_basic_password == NULL && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "get_access_token_from_refresh - oauth2 - client '%s' is invalid or is not confidential, origin: %s", request->auth_basic_user, ip_source);
          has_issues = 1;
        }
        json_decref(j_client);
      }
      time(&now);
      issued_for = get_client_hostname(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
      scope_joined = join_json_string_array(json_object_get(json_object_get(j_refresh, "token"), "scope"), " ");
      if (scope_joined == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_access_token_from_refresh - oauth2 - Error join_json_string_array");
        has_error = 1;
      }
      if (update_refresh_token(config,
                               json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "gpgr_id")),
                               (json_object_get(json_object_get(j_refresh, "token"), "rolling_expiration") == json_true())?json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "duration")):0,
                               0,
                               now) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_access_token_from_refresh - oauth2 - Error update_refresh_token");
        has_error = 1;
      }
      if (!has_error && !has_issues) {
        j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "username")));
        if (check_result_value(j_user, G_OK)) {
          if ((access_token = generate_access_token(config,
                                                    json_string_value(json_object_get(json_object_get(j_refresh, "token"), "username")),
                                                    json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")),
                                                    json_object_get(j_user, "user"),
                                                    scope_joined,
                                                    now,
                                                    ip_source)) != NULL) {
            if (serialize_access_token(config,
                                       GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN,
                                       json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "gpgr_id")),
                                       json_string_value(json_object_get(json_object_get(j_refresh, "token"), "username")),
                                       json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")),
                                       scope_joined,
                                       now,
                                       issued_for,
                                       u_map_get_case(request->map_header, "user-agent"),
                                       access_token) == G_OK) {
              json_body = json_pack("{sssssIsssi}",
                                    "access_token", access_token,
                                    "token_type", "bearer",
                                    "expires_in", config->access_token_duration,
                                    "scope", scope_joined,
                                    "iat", now);
              ulfius_set_json_body_response(response, 200, json_body);
              json_decref(json_body);
              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, "response_type", "refresh_token", NULL);
              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, NULL);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "get_access_token_from_refresh - oauth2 - Error serialize_access_token");
              response->status = 500;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_access_token_from_refresh - oauth2 - Error generate_client_access_token");
            response->status = 500;
          }
          o_free(access_token);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "get_access_token_from_refresh - oauth2 - Error glewlwyd_plugin_callback_get_user, origin: %s", ip_source);
          response->status = 500;
        }
        json_decref(j_user);
      } else if (has_issues) {
        response->status = 400;
      } else {
        response->status = 500;
      }
      o_free(issued_for);
    } else if (check_result_value(j_refresh, G_ERROR_NOT_FOUND)) {
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Token invalid at IP Address %s", get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
      response->status = 400;
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_INVALID_REFRESH_TOKEN, 1, "plugin", config->name, NULL);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_access_token_from_refresh - oauth2 - Error validate_refresh_token");
      response->status = 500;
    }
    json_decref(j_refresh);
    o_free(scope_joined);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "get_access_token_from_refresh - oauth2 - Error token empty or missing, origin: %s", ip_source);
    response->status = 400;
  }
  return U_CALLBACK_CONTINUE;
}

/**
 * Invalidate a refresh token
 */
static int delete_refresh_token (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  const char * refresh_token = u_map_get(request->map_post_body, "refresh_token"), * ip_source = get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
  json_t * j_refresh, * j_client;
  time_t now;
  char * issued_for;
  int has_issues = 0;

  if (refresh_token != NULL && !o_strnullempty(refresh_token)) {
    j_refresh = validate_refresh_token(config, refresh_token);
    if (check_result_value(j_refresh, G_OK)) {
      if (json_object_get(json_object_get(j_refresh, "token"), "client_id") != json_null()) {
        j_client = check_client_valid(config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), request->auth_basic_user, request->auth_basic_password, NULL, GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN, 0, ip_source);
        if (!check_result_value(j_client, G_OK)) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "delete_refresh_token - oauth2 - client '%s' is invalid, origin: %s", request->auth_basic_user, ip_source);
          has_issues = 1;
        } else if (request->auth_basic_user == NULL && request->auth_basic_password == NULL && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "delete_refresh_token - oauth2 - client '%s' is invalid or is not confidential, origin: %s", request->auth_basic_user, ip_source);
          has_issues = 1;
        }
        json_decref(j_client);
      }
      if (!has_issues) {
        time(&now);
        issued_for = get_client_hostname(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header);
        if (update_refresh_token(config, json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "gpgr_id")), 0, 1, now) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "delete_refresh_token - oauth2 - Error update_refresh_token");
          response->status = 500;
        }
        o_free(issued_for);
      } else {
        response->status = 400;
      }
    } else if (check_result_value(j_refresh, G_ERROR_NOT_FOUND)) {
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Token invalid at IP Address %s", get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
      response->status = 400;
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_INVALID_REFRESH_TOKEN, 1, "plugin", config->name, NULL);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "delete_refresh_token - oauth2 - Error validate_refresh_token");
      response->status = 500;
    }
    json_decref(j_refresh);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "delete_refresh_token - oauth2 - token missing or empty, origin: %s", get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
    response->status = 400;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_check_glewlwyd_session(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  json_t * j_session, * j_user;
  int ret = U_CALLBACK_UNAUTHORIZED;

  if (!o_strnullempty(u_map_get(request->map_url, "impersonate"))) {
    if (config->glewlwyd_config->glewlwyd_config->admin_session_authentication & GLEWLWYD_SESSION_AUTH_COOKIE) {
      j_session = config->glewlwyd_config->glewlwyd_callback_check_session_valid(config->glewlwyd_config, request, config->glewlwyd_config->glewlwyd_config->admin_scope);
      if (check_result_value(j_session, G_OK)) {
        j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, u_map_get(request->map_url, "impersonate"));
        if (check_result_value(j_user, G_OK)) {
          if (ulfius_set_response_shared_data(response, json_pack("{ss}", "username", u_map_get(request->map_url, "impersonate")), (void (*)(void *))&json_decref) != U_OK) {
            ret = U_CALLBACK_ERROR;
          } else {
            ret = U_CALLBACK_CONTINUE;
          }
        }
        json_decref(j_user);
      }
      json_decref(j_session);
    }
  } else {
    j_session = config->glewlwyd_config->glewlwyd_callback_check_session_valid(config->glewlwyd_config, request, NULL);
    if (check_result_value(j_session, G_OK)) {
      if (ulfius_set_response_shared_data(response, json_pack("{ss}", "username", json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username"))), (void (*)(void *))&json_decref) != U_OK) {
        ret = U_CALLBACK_ERROR;
      } else {
        ret = U_CALLBACK_CONTINUE;
      }
    }
    json_decref(j_session);
  }
  return ret;
}

static int callback_check_glewlwyd_session_or_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  json_t * j_session, * j_user, * j_introspect;
  int ret = U_CALLBACK_UNAUTHORIZED;

  if (u_map_get_case(request->map_header, HEADER_AUTHORIZATION) != NULL && o_strlen(u_map_get_case(request->map_header, HEADER_AUTHORIZATION)) >= o_strlen(HEADER_PREFIX_BEARER)) {
    j_introspect = get_token_metadata(config, (u_map_get_case(request->map_header, HEADER_AUTHORIZATION) + o_strlen(HEADER_PREFIX_BEARER)), "access_token", NULL);
    if (check_result_value(j_introspect, G_OK) && json_object_get(json_object_get(j_introspect, "token"), "active") == json_true()) {
      ret = callback_check_glewlwyd_access_token(request, response, (void*)config->glewlwyd_resource_config);
    }
    json_decref(j_introspect);
  } else {
    if (!o_strnullempty(u_map_get(request->map_url, "impersonate"))) {
      if (config->glewlwyd_config->glewlwyd_config->admin_session_authentication & GLEWLWYD_SESSION_AUTH_COOKIE) {
        j_session = config->glewlwyd_config->glewlwyd_callback_check_session_valid(config->glewlwyd_config, request, config->glewlwyd_config->glewlwyd_config->admin_scope);
        if (check_result_value(j_session, G_OK)) {
          j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, u_map_get(request->map_url, "impersonate"));
          if (check_result_value(j_user, G_OK)) {
            if (ulfius_set_response_shared_data(response, json_pack("{ss}", "username", u_map_get(request->map_url, "impersonate")), (void (*)(void *))&json_decref) != U_OK) {
              ret = U_CALLBACK_ERROR;
            } else {
              ret = U_CALLBACK_CONTINUE;
            }
          }
          json_decref(j_user);
        }
        json_decref(j_session);
      }
    } else {
      j_session = config->glewlwyd_config->glewlwyd_callback_check_session_valid(config->glewlwyd_config, request, NULL);
      if (check_result_value(j_session, G_OK)) {
        if (ulfius_set_response_shared_data(response, json_pack("{ss}", "username", json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username"))), (void (*)(void *))&json_decref) != U_OK) {
          ret = U_CALLBACK_ERROR;
        } else {
          ret = U_CALLBACK_CONTINUE;
        }
      }
      json_decref(j_session);
    }
  }
  return ret;
}

static int callback_oauth2_authorization(const struct _u_request * request, struct _u_response * response, void * user_data) {
  const char * response_type = u_map_get(request->map_url, "response_type");
  int result = U_CALLBACK_CONTINUE;
  char * redirect_url, * state_encoded = NULL, * state_param = NULL;

  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");

  if (u_map_get(request->map_url, "state") != NULL) {
    state_encoded = ulfius_url_encode(u_map_get(request->map_url, "state"));
    state_param = msprintf("&state=%s", state_encoded);
    o_free(state_encoded);
  } else {
    state_param = o_strdup("");
  }
  if (0 == o_strcmp("code", response_type)) {
    if (is_authorization_type_enabled((struct _oauth2_config *)user_data, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE) && u_map_get(request->map_url, "redirect_uri") != NULL) {
      result = check_auth_type_auth_code_grant(request, response, user_data);
    } else {
      if (u_map_get(request->map_url, "redirect_uri") != NULL) {
        response->status = 302;
        redirect_url = msprintf("%s#error=unsupported_response_type%s", u_map_get(request->map_url, "redirect_uri"), state_param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      } else {
        response->status = 403;
      }
    }
  } else if (0 == o_strcmp("token", response_type)) {
    if (is_authorization_type_enabled((struct _oauth2_config *)user_data, GLEWLWYD_AUTHORIZATION_TYPE_IMPLICIT) && u_map_get(request->map_url, "redirect_uri") != NULL) {
      result = check_auth_type_implicit_grant(request, response, user_data);
    } else {
      if (u_map_get(request->map_url, "redirect_uri") != NULL) {
        response->status = 302;
        redirect_url = msprintf("%s#error=unsupported_response_type%s", u_map_get(request->map_url, "redirect_uri"), state_param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      } else {
        response->status = 403;
      }
    }
  } else {
    if (u_map_get(request->map_url, "redirect_uri") != NULL) {
      response->status = 302;
      redirect_url = msprintf("%s#error=unsupported_response_type%s", u_map_get(request->map_url, "redirect_uri"), state_param);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
    } else {
      response->status = 403;
    }
  }
  o_free(state_param);

  return result;
}

static int callback_oauth2_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  const char * grant_type = u_map_get(request->map_post_body, "grant_type");
  int result = U_CALLBACK_CONTINUE;

  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");

  if (0 == o_strcmp("authorization_code", grant_type)) {
    if (is_authorization_type_enabled(config, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE)) {
      result = check_auth_type_access_token_request(request, response, user_data);
    } else {
      response->status = 403;
    }
  } else if (0 == o_strcmp("password", grant_type)) {
    if (is_authorization_type_enabled(config, GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS)) {
      result = check_auth_type_resource_owner_pwd_cred(request, response, user_data);
    } else {
      response->status = 403;
    }
  } else if (0 == o_strcmp("client_credentials", grant_type)) {
    if (is_authorization_type_enabled(config, GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS)) {
      result = check_auth_type_client_credentials_grant(request, response, user_data);
    } else {
      response->status = 403;
    }
  } else if (0 == o_strcmp("refresh_token", grant_type)) {
    result = get_access_token_from_refresh(request, response, user_data);
  } else if (0 == o_strcmp("delete_token", grant_type)) {
    result = delete_refresh_token(request, response, user_data);
  } else if (0 == o_strcmp("urn:ietf:params:oauth:grant-type:device_code", grant_type)) {
    result = check_auth_type_device_code(request, response, user_data);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "callback_oauth2_token - oauth2 - Unknown grant_type '%s', origin: %s", grant_type, get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
    response->status = 400;
  }
  return result;
}

static int callback_oauth2_get_profile(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  json_t * j_profile = config->glewlwyd_config->glewlwyd_plugin_callback_get_user_profile(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")));

  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");

  if (check_result_value(j_profile, G_OK)) {
    json_object_del(json_object_get(j_profile, "user"), "scope");
    json_object_del(json_object_get(j_profile, "user"), "enabled");
    json_object_del(json_object_get(j_profile, "user"), "source");
    json_object_del(json_object_get(j_profile, "user"), "last_login");
    ulfius_set_json_body_response(response, 200, json_object_get(j_profile, "user"));
  } else {
    response->status = 404;
  }
  json_decref(j_profile);
  return U_CALLBACK_CONTINUE;
}

static int callback_oauth2_refresh_token_list_get(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  size_t offset = 0, limit = GLEWLWYD_DEFAULT_LIMIT_SIZE;
  long int l_converted = 0;
  char * endptr = NULL, * sort = NULL;
  json_t * j_refresh_list;

  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");

  if (u_map_get(request->map_url, "offset") != NULL) {
    l_converted = strtol(u_map_get(request->map_url, "offset"), &endptr, 10);
    if (!(*endptr) && l_converted > 0) {
      offset = (size_t)l_converted;
    }
  }
  if (u_map_get(request->map_url, "limit") != NULL) {
    l_converted = strtol(u_map_get(request->map_url, "limit"), &endptr, 10);
    if (!(*endptr) && l_converted > 0) {
      limit = (size_t)l_converted;
    }
  }
  if (0 == o_strcmp(u_map_get(request->map_url, "sort"), "authorization_type") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "client_id") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "issued_at") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "last_seen") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "expires_at") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "issued_for") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "user_agent") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "enabled") || 0 == o_strcmp(u_map_get(request->map_url, "sort"), "rolling_expiration")) {
    sort = msprintf("gpgr_%s%s", u_map_get(request->map_url, "sort"), (u_map_get_case(request->map_url, "desc")!=NULL?" DESC":" ASC"));
  }
  j_refresh_list = refresh_token_list_get(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), u_map_get(request->map_url, "pattern"), offset, limit, sort);
  if (check_result_value(j_refresh_list, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_refresh_list, "refresh_token"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_oauth2_refresh_token_list_get - Error refresh_token_list_get");
    response->status = 500;
  }
  o_free(sort);
  json_decref(j_refresh_list);
  return U_CALLBACK_CONTINUE;
}

static int callback_oauth2_disable_refresh_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  int res;

  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");

  if ((res = refresh_token_disable(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), u_map_get(request->map_url, "token_hash"), get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header))) == G_ERROR_NOT_FOUND) {
    response->status = 404;
  } else if (res == G_ERROR_PARAM) {
    response->status = 400;
  } else if (res != G_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_oauth2_disable_refresh_token - Error refresh_token_disable");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

/**
 * Generates a new device_authorization if the client is allowed
 */
static int callback_oauth2_device_authorization(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  const char * ip_source = get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header), * client_id = request->auth_basic_user, * client_secret = request->auth_basic_password;
  char * verification_uri, * verification_uri_complete, * plugin_url = config->glewlwyd_config->glewlwyd_callback_get_plugin_external_url(config->glewlwyd_config, json_string_value(json_object_get(config->j_params, "name")));
  json_t * j_client, * j_body, * j_result;

  if (client_id == NULL && u_map_get(request->map_post_body, "client_id") != NULL) {
    client_id = u_map_get(request->map_post_body, "client_id");
  }
  if (client_secret == NULL && u_map_get(request->map_post_body, "client_secret") != NULL) {
    client_secret = u_map_get(request->map_post_body, "client_secret");
  }
  if (!o_strnullempty(u_map_get(request->map_post_body, "scope"))) {
    j_client = check_client_valid(config,
                                 client_id,
                                 client_id,
                                 client_secret,
                                 NULL,
                                 GLEWLWYD_AUTHORIZATION_TYPE_DEVICE_AUTHORIZATION,
                                 0,
                                 ip_source);
    if (check_result_value(j_client, G_OK)) {
      client_id = json_string_value(json_object_get(json_object_get(j_client, "client"), "client_id"));
      j_result = generate_device_authorization(config, client_id, u_map_get(request->map_post_body, "scope"), ip_source);
      if (check_result_value(j_result, G_OK)) {
          verification_uri = msprintf("%s/device", plugin_url);
          verification_uri_complete = msprintf("%s/device?code=%s", plugin_url, json_string_value(json_object_get(json_object_get(j_result, "authorization"), "user_code")));
          j_body = json_pack("{sOsOsssssOsO}",
                             "device_code", json_object_get(json_object_get(j_result, "authorization"), "device_code"),
                             "user_code", json_object_get(json_object_get(j_result, "authorization"), "user_code"),
                             "verification_uri", verification_uri,
                             "verification_uri_complete", verification_uri_complete,
                             "expires_in", json_object_get(config->j_params, "device-authorization-expiration"),
                             "interval", json_object_get(config->j_params, "device-authorization-interval"));
          ulfius_set_json_body_response(response, 200, j_body);
          json_decref(j_body);
          o_free(verification_uri);
          o_free(verification_uri_complete);
          config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_DEVICE_CODE, 1, "plugin", config->name, NULL);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_oauth2_device_authorization oauth2 - Error generate_device_authorization");
        j_body = json_pack("{ss}", "error", "server_error");
        ulfius_set_json_body_response(response, 500, j_body);
        json_decref(j_body);
      }
      json_decref(j_result);
    } else {
      j_body = json_pack("{ss}", "error", "unauthorized_client");
      ulfius_set_json_body_response(response, 403, j_body);
      json_decref(j_body);
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_UNAUTHORIZED_CLIENT, 1, "plugin", config->name, NULL);
    }
    json_decref(j_client);
  } else {
    j_body = json_pack("{ss}", "error", "invalid_scope");
    ulfius_set_json_body_response(response, 400, j_body);
    json_decref(j_body);
  }
  o_free(plugin_url);
  return U_CALLBACK_CONTINUE;
}

/**
 * Verifies the device code by the user
 */
static int callback_oauth2_device_verification(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  char * redirect_url = NULL;
  struct _u_map param;
  json_t * j_result, * j_session;

  if (!!o_strnullempty(u_map_get(request->map_url, "code"))) {
    if (u_map_init(&param) == U_OK) {
      u_map_put(&param, "prompt", "device");
      response->status = 302;
      redirect_url = get_login_url(config, request, "device", NULL, NULL, &param);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      u_map_clean(&param);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_oauth2_device_verification - Error u_map_init");
      response->status = 500;
    }
  } else if (o_strlen(u_map_get(request->map_url, "code")) != (GLEWLWYD_DEVICE_AUTH_USER_CODE_LENGTH+1)) {
    if (u_map_init(&param) == U_OK) {
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Code invalid at IP Address %s", get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
      u_map_put(&param, "prompt", "deviceCodeError");
      response->status = 302;
      redirect_url = get_login_url(config, request, "device", NULL, NULL, &param);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      u_map_clean(&param);
      config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_INVALID_DEVICE_CODE, 1, "plugin", config->name, NULL);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_oauth2_device_verification - Error u_map_init");
      response->status = 500;
    }
  } else {
    if (u_map_init(&param) == U_OK) {
      j_result = validate_device_auth_user_code(config, u_map_get(request->map_url, "code"));
      if (check_result_value(j_result, G_OK)) {
        if (u_map_has_key(request->map_url, "g_continue")) {
          j_session = validate_session_client_scope(config, request, json_string_value(json_object_get(json_object_get(j_result, "device_auth"), "client_id")), json_string_value(json_object_get(json_object_get(j_result, "device_auth"), "scope")));
          if (check_result_value(j_session, G_OK)) {
            if (validate_device_authorization_scope(config, json_integer_value(json_object_get(json_object_get(j_result, "device_auth"), "gpgda_id")), json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered"))) == G_OK) {
              response->status = 302;
              u_map_put(&param, "prompt", "deviceComplete");
              redirect_url = get_login_url(config, request, "device", NULL, NULL, &param);
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 1, "plugin", config->name, "response_type", "device_code", NULL);
              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 1, "plugin", config->name, NULL);
              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, "response_type", "device_code", NULL);
              config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 1, "plugin", config->name, NULL);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "callback_oauth2_device_verification - Error validate_device_authorization_scope");
              response->status = 302;
              u_map_put(&param, "prompt", "deviceServerError");
              redirect_url = get_login_url(config, request, "device", NULL, NULL, &param);
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
            }
          } else if (check_result_value(j_session, G_ERROR_NOT_FOUND) || check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
            // Redirect to login page
            response->status = 302;
            redirect_url = get_login_url(config, request, "device", json_string_value(json_object_get(json_object_get(j_result, "device_auth"), "client_id")), json_string_value(json_object_get(json_object_get(j_result, "device_auth"), "scope")), NULL);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "callback_oauth2_device_verification - Error validate_session_client_scope");
            response->status = 302;
            u_map_put(&param, "prompt", "deviceServerError");
            redirect_url = get_login_url(config, request, "device", NULL, NULL, &param);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
          }
          json_decref(j_session);
        } else {
          // Redirect to login page
          response->status = 302;
          redirect_url = get_login_url(config, request, "device", json_string_value(json_object_get(json_object_get(j_result, "device_auth"), "client_id")), json_string_value(json_object_get(json_object_get(j_result, "device_auth"), "scope")), NULL);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
      } else if (check_result_value(j_result, G_ERROR_NOT_FOUND)) {
        y_log_message(Y_LOG_LEVEL_WARNING, "Security - Code invalid at IP Address %s", get_ip_source(request, config->glewlwyd_config->glewlwyd_config->originating_ip_header));
        response->status = 302;
        u_map_put(&param, "prompt", "deviceCodeError");
        redirect_url = get_login_url(config, request, "device", NULL, NULL, &param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
        config->glewlwyd_config->glewlwyd_plugin_callback_metrics_increment_counter(config->glewlwyd_config, GLWD_METRICS_OAUTH2_INVALID_DEVICE_CODE, 1, "plugin", config->name, NULL);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_oauth2_device_verification - Error validate_device_auth_user_code");
        response->status = 302;
        u_map_put(&param, "prompt", "deviceServerError");
        redirect_url = get_login_url(config, request, "device", NULL, NULL, &param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
      json_decref(j_result);
      u_map_clean(&param);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_oauth2_device_verification - Error u_map_init");
      response->status = 500;
    }
  }
  return U_CALLBACK_CONTINUE;
}

static int jwt_autocheck(struct _oauth2_config * config) {
  time_t now;
  char * token;
  jwt_t * jwt = NULL;
  int ret;

  time(&now);
  token = generate_access_token(config, GLEWLWYD_CHECK_JWT_USERNAME, NULL, NULL, GLEWLWYD_CHECK_JWT_SCOPE, now, NULL);
  if (token != NULL) {
    jwt = r_jwt_copy(config->glewlwyd_resource_config->jwt);
    if (r_jwt_advanced_parse(jwt, token, R_PARSE_NONE, 0) == RHN_OK && r_jwt_verify_signature(jwt, NULL, 0) == RHN_OK) {
      ret = RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "jwt_autocheck - oauth2 - Error verifying signature");
      ret = G_ERROR_PARAM;
    }
    r_jwt_free(jwt);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "jwt_autocheck - oauth2 - Error generate_access_token");
    ret = G_ERROR;
  }
  o_free(token);
  return ret;
}

static int disable_user_data(struct _oauth2_config * config, const char * username) {
  json_t * j_query;
  int res, ret = G_OK;

  do {
    j_query = json_pack("{sss{si}s{sssssi}}",
                        "table", GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE,
                        "set",
                          "gpgc_enabled", 0,
                        "where",
                          "gpgc_plugin_name", config->name,
                          "gpgc_username", username,
                          "gpgc_enabled", 1);
    res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
    json_decref(j_query);
    if (res != H_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "disable_user_data - Error disable codes");
      ret = G_ERROR;
      break;
    }

    j_query = json_pack("{sss{si}s{sssssi}}",
                        "table", GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                        "set",
                          "gpgr_enabled", 0,
                        "where",
                          "gpgr_plugin_name", config->name,
                          "gpgr_username", username,
                          "gpgr_enabled", 1);
    res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
    json_decref(j_query);
    if (res != H_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "disable_user_data - Error disable refresh tokens");
      ret = G_ERROR;
      break;
    }

    j_query = json_pack("{sss{si}s{sssssi}}",
                        "table", GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN,
                        "set",
                          "gpga_enabled", 0,
                        "where",
                          "gpga_plugin_name", config->name,
                          "gpga_username", username,
                          "gpga_enabled", 1);
    res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
    json_decref(j_query);
    if (res != H_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "disable_user_data - Error disable access tokens");
      ret = G_ERROR;
      break;
    }

    j_query = json_pack("{sss{si}s{sssss{ssss}}}",
                        "table", GLEWLWYD_PLUGIN_OAUTH2_TABLE_DEVICE_AUTHORIZATION,
                        "set",
                          "gpgda_status", 3,
                        "where",
                          "gpgda_plugin_name", config->name,
                          "gpgda_username", username,
                          "gpgda_status",
                            "operator", "raw",
                            "value", "in (0, 1)");
    res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
    json_decref(j_query);
    if (res != H_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "disable_user_data - Error disable device auth tokens");
      ret = G_ERROR;
      break;
    }
  } while (0);
  return ret;
}

json_t * plugin_module_load(struct config_plugin * config) {
  UNUSED(config);
  return json_pack("{si ss ss ss}",
                   "result", G_OK,
                   "name", "oauth2-glewlwyd",
                   "display_name", "OAuth2 plugin",
                   "description", "Plugin for legacy OAuth2 workflow");
}

int plugin_module_unload(struct config_plugin * config) {
  UNUSED(config);
  return G_OK;
}

json_t * plugin_module_init(struct config_plugin * config, const char * name, json_t * j_parameters, void ** cls) {
  const unsigned char * key;
  jwa_alg alg = R_JWA_ALG_UNKNOWN;
  pthread_mutexattr_t mutexattr;
  json_t * j_return = NULL, * j_result = NULL, * j_element = NULL;
  size_t index = 0;
  struct _oauth2_config * p_config = NULL;
  jwk_t * key_priv = NULL, * key_pub = NULL;

  y_log_message(Y_LOG_LEVEL_INFO, "Init plugin Glewlwyd Oauth2 '%s'", name);
  *cls = o_malloc(sizeof(struct _oauth2_config));
  if (*cls != NULL) {
    p_config = (struct _oauth2_config *)*cls;
    p_config->glewlwyd_resource_config = NULL;

    do {
      pthread_mutexattr_init ( &mutexattr );
      pthread_mutexattr_settype( &mutexattr, PTHREAD_MUTEX_RECURSIVE );
      if (pthread_mutex_init(&p_config->insert_lock, &mutexattr) != 0) {
        y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error initializing insert_lock");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }
      pthread_mutexattr_destroy(&mutexattr);

      p_config->name = name;
      p_config->jwt_key = NULL;
      p_config->j_params = json_incref(j_parameters);
      json_object_set_new(p_config->j_params, "name", json_string(name));
      p_config->glewlwyd_config = config;
      p_config->introspect_revoke_resource_config = NULL;
      if ((p_config->glewlwyd_resource_config = o_malloc(sizeof(struct _glewlwyd_resource_config))) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error initializing glewlwyd_resource_config");
        j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
        break;
      }

      p_config->glewlwyd_resource_config->method = G_METHOD_HEADER;
      p_config->glewlwyd_resource_config->oauth_scope = NULL;
      p_config->glewlwyd_resource_config->realm = NULL;
      p_config->glewlwyd_resource_config->accept_access_token = 1;
      p_config->glewlwyd_resource_config->accept_client_token = 0;
      j_result = check_parameters(p_config->j_params);

      if (check_result_value(j_result, G_ERROR_PARAM)) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_result, "error"));
        break;
      } else if (!check_result_value(j_result, G_OK)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error check_parameters");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }

      p_config->access_token_duration = json_integer_value(json_object_get(p_config->j_params, "access-token-duration"));
      if (!p_config->access_token_duration) {
        p_config->access_token_duration = GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT;
      }
      p_config->refresh_token_duration = json_integer_value(json_object_get(p_config->j_params, "refresh-token-duration"));
      if (!p_config->refresh_token_duration) {
        p_config->refresh_token_duration = GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT;
      }
      p_config->code_duration = json_integer_value(json_object_get(p_config->j_params, "code-duration"));
      if (!p_config->code_duration) {
        p_config->code_duration = GLEWLWYD_CODE_EXP_DEFAULT;
      }
      if (json_object_get(p_config->j_params, "refresh-token-rolling") != NULL) {
        p_config->refresh_token_rolling = json_object_get(p_config->j_params, "refresh-token-rolling")==json_true()?1:0;
      } else {
        p_config->refresh_token_rolling = 0;
      }
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE] = json_object_get(p_config->j_params, "auth-type-code-enabled")==json_true()?1:0;
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_IMPLICIT] = json_object_get(p_config->j_params, "auth-type-implicit-enabled")==json_true()?1:0;
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS] = json_object_get(p_config->j_params, "auth-type-password-enabled")==json_true()?1:0;
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS] = json_object_get(p_config->j_params, "auth-type-client-enabled")==json_true()?1:0;
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN] = json_object_get(p_config->j_params, "auth-type-refresh-enabled")==json_true()?1:0;

      if (r_jwt_init(&p_config->jwt_key) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error allocating resources for jwt_key");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }

      if (r_jwt_init(&p_config->glewlwyd_resource_config->jwt) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error allocating resources for jwt");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }

      key = (const unsigned char *)json_string_value(json_object_get(p_config->j_params, "key"));
      if (0 == o_strcmp("rsa", json_string_value(json_object_get(p_config->j_params, "jwt-type")))) {
        if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_RS256;
        } else if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_RS384;
        } else { // 512
          alg = R_JWA_ALG_RS512;
        }
      } else if (0 == o_strcmp("ecdsa", json_string_value(json_object_get(p_config->j_params, "jwt-type")))) {
        if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_ES256;
        } else if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_ES384;
        } else { // 512
          alg = R_JWA_ALG_ES512;
        }
      } else if (0 == o_strcmp("sha", json_string_value(json_object_get(p_config->j_params, "jwt-type")))) {
        if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_HS256;
        } else if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_HS384;
        } else { // 512
          alg = R_JWA_ALG_HS512;
        }
      } else if (0 == o_strcmp("rsa-pss", json_string_value(json_object_get(p_config->j_params, "jwt-type")))) { // SHA
        if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_PS256;
        } else if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_PS384;
        } else { // 512
          alg = R_JWA_ALG_PS512;
        }
      } else {
        alg = R_JWA_ALG_EDDSA;
      }

      if (r_jwt_set_sign_alg(p_config->jwt_key, alg) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error r_jwt_set_sign_alg");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }

      if (r_jwt_set_sign_alg(p_config->glewlwyd_resource_config->jwt, alg) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error r_jwt_set_sign_alg (2)");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }

      if (0 == o_strcmp("sha", json_string_value(json_object_get(p_config->j_params, "jwt-type")))) {
        if (r_jwt_add_sign_key_symmetric(p_config->jwt_key, key, o_strlen((const char *)key)) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error r_jwt_add_sign_key_symmetric");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        if (r_jwt_add_sign_key_symmetric(p_config->glewlwyd_resource_config->jwt, key, o_strlen((const char *)key)) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error r_jwt_add_sign_key_symmetric (2)");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
      } else {
        if (r_jwk_init(&key_priv) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error r_jwk_init key_priv");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        if (r_jwk_init(&key_pub) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error r_jwk_init key_pub");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        if (r_jwk_import_from_pem_der(key_priv, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, key, o_strlen((const char *)key)) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error r_jwk_import_from_pem_der key_priv");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        if (r_jwk_import_from_pem_der(key_pub, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (const unsigned char *)json_string_value(json_object_get(p_config->j_params, "cert")), json_string_length(json_object_get(p_config->j_params, "cert"))) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error r_jwk_import_from_pem_der key_pub");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        r_jwk_delete_property_str(key_priv, "kid");
        r_jwk_delete_property_str(key_pub, "kid");
        if (r_jwt_add_sign_keys(p_config->jwt_key, key_priv, NULL)  != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error r_jwt_add_sign_keys");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        if (r_jwt_add_sign_keys(p_config->glewlwyd_resource_config->jwt, NULL, key_pub) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error r_jwt_add_sign_keys_pem_der (2)");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
      }

      if (jwt_autocheck(p_config) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error jwt_autocheck");
        j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "Error jwt_autocheck");
        break;
      }

      p_config->glewlwyd_resource_config->alg = alg;

      // Add endpoints
      y_log_message(Y_LOG_LEVEL_INFO, "Add endpoints with plugin prefix %s", name);
      if (config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_authorization, (void*)*cls) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "token/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_token, (void*)*cls) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "*", name, "profile/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_glewlwyd_session_or_token, (void*)*cls) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "*", name, "profile/token/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_glewlwyd_session, (void*)*cls) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_get_profile, (void*)*cls) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "profile/token/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_refresh_token_list_get, (void*)*cls) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "DELETE", name, "profile/token/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_disable_refresh_token, (void*)*cls) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "DELETE", name, "profile/token/:token_hash", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_disable_refresh_token, (void*)*cls) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error adding endpoints");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }

      if (json_object_get(p_config->j_params, "introspection-revocation-allowed") == json_true()) {
        if ((p_config->introspect_revoke_resource_config = o_malloc(sizeof(struct _glewlwyd_resource_config))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error allocatig resources for introspect_revoke_resource_config");
          j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
          break;
        }
        p_config->introspect_revoke_resource_config->method = G_METHOD_HEADER;
        p_config->introspect_revoke_resource_config->oauth_scope = NULL;
        json_array_foreach(json_object_get(p_config->j_params, "introspection-revocation-auth-scope"), index, j_element) {
          if (p_config->introspect_revoke_resource_config->oauth_scope == NULL) {
            p_config->introspect_revoke_resource_config->oauth_scope = o_strdup(json_string_value(j_element));
          } else {
            p_config->introspect_revoke_resource_config->oauth_scope = mstrcatf(p_config->introspect_revoke_resource_config->oauth_scope, " %s", json_string_value(j_element));
          }
        }
        p_config->introspect_revoke_resource_config->realm = NULL;
        p_config->introspect_revoke_resource_config->accept_access_token = 1;
        p_config->introspect_revoke_resource_config->accept_client_token = 1;
        p_config->introspect_revoke_resource_config->jwt = r_jwt_copy(p_config->glewlwyd_resource_config->jwt);
        p_config->introspect_revoke_resource_config->alg = alg;
        if (
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "introspect/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_intropect_revoke, (void*)*cls) != G_OK ||
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "introspect/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_introspection, (void*)*cls) != G_OK ||
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "revoke/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_intropect_revoke, (void*)*cls) != G_OK ||
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "revoke/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_revocation, (void*)*cls) != G_OK
          ) {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - oauth2 - Error adding introspect/revoke endpoints");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
      }

      if (json_object_get(p_config->j_params, "auth-type-device-enabled") == json_true()) {
        if (
         config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "device_authorization/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_device_authorization, (void*)*cls) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "device/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_device_verification, (void*)*cls) != G_OK
        ) {
          y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - oauth2 - Error adding device-authorization endpoints");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        if (json_object_get(p_config->j_params, "device-authorization-expiration") == NULL) {
          json_object_set_new(p_config->j_params, "device-authorization-expiration", json_integer(GLEWLWYD_DEVICE_AUTH_DEFAUT_EXPIRATION));
        }
        if (json_object_get(p_config->j_params, "device-authorization-interval") == NULL) {
          json_object_set_new(p_config->j_params, "device-authorization-interval", json_integer(GLEWLWYD_DEVICE_AUTH_DEFAUT_INTERVAL));
        }
      }
      config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_OAUTH2_CODE, "Total number of code provided");
      config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_OAUTH2_DEVICE_CODE, "Total number of device code provided");
      config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, "Total number of refresh tokens provided");
      config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, "Total number of access tokens provided");
      config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_OAUTH2_CLIENT_ACCESS_TOKEN, "Total number of client tokens provided");
      config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_OAUTH2_UNAUTHORIZED_CLIENT, "Total number of unauthorized client attempt");
      config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_OAUTH2_INVALID_CODE, "Total number of invalid code");
      config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_OAUTH2_INVALID_DEVICE_CODE, "Total number of invalid device code");
      config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_OAUTH2_INVALID_REFRESH_TOKEN, "Total number of invalid refresh token");
      config->glewlwyd_plugin_callback_metrics_add_metric(config, GLWD_METRICS_OAUTH2_INVALID_ACCESS_TOKEN, "Total number of invalid access token");
      config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_CODE, 0, "plugin", name, NULL);
      config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 0, "plugin", name, NULL);
      config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 0, "plugin", name, NULL);
      if (json_object_get(p_config->j_params, "auth-type-code-enabled") == json_true()) {
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 0, "plugin", name, "response_type", "code", NULL);
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 0, "plugin", name, "response_type", "code", NULL);
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_INVALID_CODE, 0, "plugin", name, NULL);
      }
      if (json_object_get(p_config->j_params, "auth-type-password-enabled") == json_true()) {
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 0, "plugin", name, "response_type", "password", NULL);
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 0, "plugin", name, "response_type", "password", NULL);
      }
      if (json_object_get(p_config->j_params, "auth-type-client-enabled") == json_true()) {
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_CLIENT_ACCESS_TOKEN, 0, "plugin", name, NULL);
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_UNAUTHORIZED_CLIENT, 0, "plugin", name, NULL);
      }
      if (json_object_get(p_config->j_params, "auth-type-implicit-enabled") == json_true()) {
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 0, "plugin", name, "response_type", "token", NULL);
      }
      if (json_object_get(p_config->j_params, "auth-type-device-enabled") == json_true()) {
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_DEVICE_CODE, 0, "plugin", name, NULL);
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_INVALID_DEVICE_CODE, 0, "plugin", name, NULL);
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_REFRESH_TOKEN, 0, "plugin", name, "response_type", "device_code", NULL);
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 0, "plugin", name, "response_type", "device_code", NULL);
      }
      if (json_object_get(p_config->j_params, "auth-type-refresh-enabled") == json_true()) {
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_USER_ACCESS_TOKEN, 0, "plugin", name, "response_type", "refresh_token", NULL);
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_INVALID_REFRESH_TOKEN, 0, "plugin", name, NULL);
      }
      if (json_object_get(p_config->j_params, "introspection-revocation-allowed") == json_true()) {
        config->glewlwyd_plugin_callback_metrics_increment_counter(config, GLWD_METRICS_OAUTH2_INVALID_ACCESS_TOKEN, 0, "plugin", name, NULL);
      }

    } while (0);
    json_decref(j_result);
    r_jwk_free(key_priv);
    r_jwk_free(key_pub);
    if (j_return == NULL) {
      j_return = json_pack("{si}", "result", G_OK);
    } else {
      if (p_config != NULL) {
        if (p_config->introspect_revoke_resource_config != NULL) {
          o_free(p_config->introspect_revoke_resource_config->oauth_scope);
          o_free(p_config->introspect_revoke_resource_config->realm);
          r_jwt_free(p_config->introspect_revoke_resource_config->jwt);
          o_free(p_config->introspect_revoke_resource_config);
        }
        if (p_config->glewlwyd_resource_config != NULL) {
          o_free(p_config->glewlwyd_resource_config->oauth_scope);
          o_free(p_config->glewlwyd_resource_config->realm);
          r_jwt_free(p_config->glewlwyd_resource_config->jwt);
          o_free(p_config->glewlwyd_resource_config);
        }
        r_jwt_free(p_config->jwt_key);
        json_decref(p_config->j_params);
        pthread_mutex_destroy(&p_config->insert_lock);
        o_free(p_config);
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "plugin_module_init - oauth2 - Error allocating resources for cls");
    o_free(*cls);
    *cls = NULL;
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

int plugin_module_close(struct config_plugin * config, const char * name, void * cls) {
  UNUSED(name);
  if (cls != NULL) {
    y_log_message(Y_LOG_LEVEL_INFO, "Close plugin Glewlwyd Oauth2 '%s'", name);
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "auth/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "token/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "profile/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "profile/token/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "DELETE", name, "profile/token/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "DELETE", name, "profile/token/:token_hash");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "*", name, "profile/*");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "*", name, "profile/token/*");

    if (((struct _oauth2_config *)cls)->introspect_revoke_resource_config != NULL) {
      config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "introspect/");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "revoke/");
      o_free(((struct _oauth2_config *)cls)->introspect_revoke_resource_config->oauth_scope);
      r_jwt_free(((struct _oauth2_config *)cls)->introspect_revoke_resource_config->jwt);
      o_free(((struct _oauth2_config *)cls)->introspect_revoke_resource_config);
    }
    if (((struct _oauth2_config *)cls)->glewlwyd_resource_config != NULL) {
      o_free(((struct _oauth2_config *)cls)->glewlwyd_resource_config->oauth_scope);
      r_jwt_free(((struct _oauth2_config *)cls)->glewlwyd_resource_config->jwt);
      o_free(((struct _oauth2_config *)cls)->glewlwyd_resource_config);
    }
    if (json_object_get(((struct _oauth2_config *)cls)->j_params, "auth-type-device-enabled") == json_true()) {
      config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "device_authorization/");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "device/");
    }
    r_jwt_free(((struct _oauth2_config *)cls)->jwt_key);
    json_decref(((struct _oauth2_config *)cls)->j_params);
    pthread_mutex_destroy(&((struct _oauth2_config *)cls)->insert_lock);
    o_free(cls);
  }
  return G_OK;
}

int plugin_user_revoke(struct config_plugin * config, const char * username, void * cls) {
  UNUSED(config);
  // Disable all data for user 'username', then remove entry in subject identifier table
  if (disable_user_data((struct _oauth2_config *)cls, username) == G_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "plugin_user_revoke - oauth2 - Error disable_user_data");
    return G_ERROR;
  }
}

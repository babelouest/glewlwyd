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
 * Copyright 2016-2019 Nicolas Mora <mail@babelouest.org>
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
#include <jansson.h>
#include <jwt.h>
#include <yder.h>
#include <orcania.h>
#include <ulfius.h>
#include "../glewlwyd-common.h"
#include "../../docs/resources/ulfius/glewlwyd_resource.h"

#define OAUTH2_SALT_LENGTH 16

#define GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT 3600
#define GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT 1209600
#define GLEWLWYD_CODE_EXP_DEFAULT 600

#define GLEWLWYD_CHECK_JWT_USERNAME "myrddin"
#define GLEWLWYD_CHECK_JWT_SCOPE    "caledonia"

#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE                "gpg_code"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE_SCOPE          "gpg_code_scope"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN       "gpg_refresh_token"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN_SCOPE "gpg_refresh_token_scope"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN        "gpg_access_token"
#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN_SCOPE  "gpg_access_token_scope"

// Authorization types available
#define GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE                  0
#define GLEWLWYD_AUTHORIZATION_TYPE_IMPLICIT                            1
#define GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS 2
#define GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS                  3
#define GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN                       4
#define GLEWLWYD_AUTHORIZATION_TYPE_DELETE_TOKEN                        5

struct _oauth2_config {
  struct config_plugin             * glewlwyd_config;
  jwt_t                            * jwt_key;
  json_t                           * j_params;
  unsigned long                      access_token_duration;
  json_int_t                         refresh_token_duration;
  unsigned short int                 refresh_token_rolling;
  unsigned short int                 auth_type_enabled[5];
  pthread_mutex_t                    insert_lock;
  struct _glewlwyd_resource_config * glewlwyd_resource_config;
};

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
        value = url_encode((char *)u_map_get(map_url, keys[i]));
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
        value = url_encode((char *)u_map_get(map_post_body, keys[i]));
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

static int serialize_access_token(struct _oauth2_config * config, uint auth_type, json_int_t gpgr_id, const char * username, const char * client_id, const char * scope_list, time_t now, const char * issued_for, const char * user_agent) {
  json_t * j_query, * j_last_id;
  int res, ret, i;
  char * issued_at_clause, ** scope_array = NULL;
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_access_token - Error pthread_mutex_lock");
  } else {
    if (issued_for != NULL && now > 0) {
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        issued_at_clause = msprintf("FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        issued_at_clause = msprintf("EXTRACT(TIMESTAMP FROM EPOCH %u)", (now));
      } else { // HOEL_DB_TYPE_SQLITE
        issued_at_clause = msprintf("%u", (now));
      }
      j_query = json_pack("{sss{sisososos{ss}ssss}}",
                          "table",
                          GLEWLWYD_PLUGIN_OAUTH2_TABLE_ACCESS_TOKEN,
                          "values",
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
                            user_agent!=NULL?user_agent:"");
      o_free(issued_at_clause);
      res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
        if (j_last_id != NULL) {
          if (split_string(scope_list, " ", &scope_array) > 0) {
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
                y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_access_token - Error executing j_query (2)");
                ret = G_ERROR_DB;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_access_token - Error json_pack");
              ret = G_ERROR;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_access_token - Error split_string");
            ret = G_ERROR;
          }
          free_string_array(scope_array);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_access_token - Error h_last_insert_id");
          ret = G_ERROR_DB;
        }
        json_decref(j_last_id);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_access_token - Error executing j_query (1)");
        ret = G_ERROR_DB;
      }
    } else {
      ret = G_ERROR_PARAM;
    }
    pthread_mutex_unlock(&config->insert_lock);
  }
  return ret;
}

/**
 * Generates a client_access_token from the specified parameters that are considered valid
 */
static char * generate_client_access_token(struct _oauth2_config * config, const char * client_id, const char * issued_for, const char * scope_list, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  char salt[OAUTH2_SALT_LENGTH + 1] = {0};
  
  jwt = jwt_dup(config->jwt_key);
  if (jwt != NULL) {
    // Build jwt payload
    rand_string(salt, OAUTH2_SALT_LENGTH);
    jwt_add_grant(jwt, "salt", salt);
    jwt_add_grant(jwt, "client_id", client_id);
    jwt_add_grant(jwt, "type", "client_token");
    jwt_add_grant(jwt, "scope", scope_list);
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->access_token_duration);
    token = jwt_encode_str(jwt);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_client_access_token - Error generating token");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_client_access_token - Error cloning jwt");
  }
  jwt_free(jwt);
  return token;
}

static char * generate_access_token(struct _oauth2_config * config, const char * username, const char * scope_list, time_t now) {
  char salt[OAUTH2_SALT_LENGTH + 1] = {0};
  jwt_t * jwt = NULL;
  char * token = NULL;
  
  if ((jwt = jwt_dup(config->jwt_key)) != NULL) {
    rand_string(salt, OAUTH2_SALT_LENGTH);
    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "salt", salt);
    jwt_add_grant(jwt, "type", "access_token");
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->access_token_duration);
    if (scope_list != NULL) {
      jwt_add_grant(jwt, "scope", scope_list);
    }
    token = jwt_encode_str(jwt);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_access_token - oauth2 - Error jwt_encode_str");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_access_token - oauth2 - Error jwt_dup");
  }
  jwt_free(jwt);
  return token;
}

static json_t * serialize_refresh_token(struct _oauth2_config * config, uint auth_type, json_int_t gpgc_id, const char * username, const char * client_id, const char * scope_list, time_t now, json_int_t duration, uint rolling, const char * token, const char * issued_for, const char * user_agent) {
  char * token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token);
  json_t * j_query, * j_return, * j_last_id;
  int res, i;
  char * issued_at_clause, * expires_at_clause, ** scope_array = NULL;
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_refresh_token - Error pthread_mutex_lock");
  } else {
    if (token_hash != NULL && username != NULL && issued_for != NULL && now > 0 && duration > 0) {
      json_error_t error;
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        issued_at_clause = msprintf("FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        issued_at_clause = msprintf("EXTRACT(TIMESTAMP FROM EPOCH %u)", (now));
      } else { // HOEL_DB_TYPE_SQLITE
        issued_at_clause = msprintf("%u", (now));
      }
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)duration));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("EXTRACT(TIMESTAMP FROM EPOCH %u)", (now + (unsigned int)duration ));
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("%u", (now + (unsigned int)duration));
      }
      j_query = json_pack_ex(&error, 0, "{sss{si so ss so s{ss} s{ss} sI si ss ss ss}}",
                          "table",
                          GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                          "values",
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
      res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
        if (j_last_id != NULL) {
          if (split_string(scope_list, " ", &scope_array) > 0) {
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
                y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_refresh_token - Error executing j_query (2)");
                j_return = json_pack("{si}", "result", G_ERROR_DB);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_refresh_token - Error json_pack");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_refresh_token - Error split_string");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          free_string_array(scope_array);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_refresh_token - Error h_last_insert_id");
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        json_decref(j_last_id);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 serialize_refresh_token - Error executing j_query (1)");
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

static char * generate_refresh_token(struct _oauth2_config * config, const char * client_id, const char * username, const uint auth_type, const char * issued_for, const char * scope_list, time_t now) {
  jwt_t * jwt;
  char * token = NULL;
  char salt[OAUTH2_SALT_LENGTH + 1] = {0};
  
  if ((jwt = jwt_dup(config->jwt_key)) != NULL) {
    // Build jwt payload
    rand_string(salt, OAUTH2_SALT_LENGTH);
    jwt_add_grant(jwt, "salt", salt);
    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "type", "refresh_token");
    jwt_add_grant_int(jwt, "iat", now);
    if (scope_list != NULL) {
      jwt_add_grant(jwt, "scope", scope_list);
    }
    if (client_id != NULL) {
      jwt_add_grant(jwt, "client_id", client_id);
    }
    token = jwt_encode_str(jwt);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_refresh_token - generating token");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_refresh_token - Error cloning jwt");
  }
  jwt_free(jwt);
  return token;
}

static int is_authorization_type_enabled(struct _oauth2_config * config, uint authorization_type) {
  return (authorization_type <= 4)?config->auth_type_enabled[authorization_type]:0;
}

static json_t * check_client_valid(struct _oauth2_config * config, const char * client_id, const char * client_header_login, const char * client_header_password, const char * redirect_uri, const char * scope_list, unsigned short authorization_type) {
  json_t * j_client, * j_element, * j_return;
  int uri_found, authorization_type_enabled;
  size_t index;
  
  if (client_id == NULL) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_client_valid - Error client_id is NULL");
    return json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (client_header_login != NULL && 0 != o_strcmp(client_header_login, client_id)) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_client_valid - Error, client_id specified is different from client_id in the basic auth header");
    return json_pack("{si}", "result", G_ERROR_PARAM);
  }
  j_client = config->glewlwyd_config->glewlwyd_callback_check_client_valid(config->glewlwyd_config, client_id, client_header_password, scope_list);
  if (check_result_value(j_client, G_OK)) {
    if (client_header_password != NULL && json_object_get(json_object_get(j_client, "client"), "confidential") != json_true()) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_client_valid - Error, confidential client must be authentified with its password");
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
        }
      }
      if (!uri_found) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_client_valid - Error, callback_uri '%s' is invalid for the client '%s'", redirect_uri, client_id);
      }
      if (!authorization_type_enabled) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_client_valid - Error, authorization type is not enabled for the client '%s'", client_id);
      }
      if (uri_found && authorization_type_enabled) {
        j_return = json_pack("{sisO}", "result", G_OK, "client", json_object_get(j_client, "client"));
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_client_valid - Error, client '%s' is invalid", client_id);
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  json_decref(j_client);
  return j_return;
}

static char * generate_authorization_code(struct _oauth2_config * config, const char * username, const char * client_id, const char * scope_list, const char * redirect_uri, const char * issued_for, const char * user_agent) {
  char * code = NULL, * code_hash = NULL, * expiration_clause, ** scope_array = NULL;
  json_t * j_query, * j_code_id;
  int res, i;
  time_t now;

  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_authorization_code - Error pthread_mutex_lock");
  } else {
    code = o_malloc(33*sizeof(char));
    if (code != NULL) {
      if (rand_string(code, 32) != NULL) {
        code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code);
        if (code_hash != NULL) {
          time(&now);
          if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
            expiration_clause = msprintf("FROM_UNIXTIME(%u)", (now + GLEWLWYD_CODE_EXP_DEFAULT ));
          } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
            expiration_clause = msprintf("EXTRACT(TIMESTAMP FROM EPOCH %u)", (now + GLEWLWYD_CODE_EXP_DEFAULT ));
          } else { // HOEL_DB_TYPE_SQLITE
            expiration_clause = msprintf("%u", (now + GLEWLWYD_CODE_EXP_DEFAULT ));
          }
          j_query = json_pack("{sss{sssssssssssss{ss}}}",
                              "table",
                              GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE,
                              "values",
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
                                  expiration_clause);
          o_free(expiration_clause);
          res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
          json_decref(j_query);
          if (res != H_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_authorization_code - Error executing j_query (1)");
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
                if (split_string(scope_list, " ", &scope_array) > 0) {
                  for (i=0; scope_array[i] != NULL; i++) {
                    json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOss}", "gpgc_id", j_code_id, "gpgcs_scope", scope_array[i]));
                  }
                  res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
                  json_decref(j_query);
                  if (res != H_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_authorization_code - Error executing j_query (2)");
                    o_free(code);
                    code = NULL;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_authorization_code - Error split_string");
                  o_free(code);
                  code = NULL;
                }
                free_string_array(scope_array);
                json_decref(j_code_id);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_authorization_code - Error h_last_insert_id");
                o_free(code);
                code = NULL;
              }
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_authorization_code - Error glewlwyd_callback_generate_hash");
          o_free(code);
          code = NULL;
        }
        o_free(code_hash);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_authorization_code - Error rand_string");
        o_free(code);
        code = NULL;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 generate_authorization_code - Error allocating resources for code");
    }
    pthread_mutex_unlock(&config->insert_lock);
  }

  return code;
}

static char * get_login_url(struct _oauth2_config * config, const struct _u_request * request, const char * url, const char * client_id, const char * scope_list) {
  char * plugin_url = config->glewlwyd_config->glewlwyd_callback_get_plugin_external_url(config->glewlwyd_config, json_string_value(json_object_get(config->j_params, "url"))),
       * url_params = generate_query_parameters(request->map_url, NULL),
       * url_callback = msprintf("%s/%s?%s", plugin_url, url, url_params),
       * login_url = config->glewlwyd_config->glewlwyd_callback_get_login_url(config->glewlwyd_config, client_id, scope_list, url_callback);
  o_free(plugin_url);
  o_free(url_params);
  o_free(url_callback);
  return login_url;
}

static json_t * get_scope_parameters(struct _oauth2_config * config, const char * scope) {
  json_t * j_element, * j_return = NULL;
  size_t index;
  
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
  
  j_query = json_pack("{sss{si}s{sI}}",
                      "table",
                      GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE,
                      "set",
                        "gpgc_enabled",
                        0,
                      "where",
                        "gpgc_id",
                        gpgc_id);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 disable_authorization_code - Error executing j_query");
    return G_ERROR_DB;
  }
}

static json_t * validate_authorization_code(struct _oauth2_config * config, const char * code, const char * client_id, const char * redirect_uri) {
  char * code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code), * expiration_clause = NULL, * scope_list = NULL, * tmp;
  json_t * j_query, * j_result = NULL, * j_result_scope = NULL, * j_return, * j_element, * j_scope_param;
  int res;
  size_t index;
  json_int_t maximum_duration = config->refresh_token_duration;
  int rolling_refresh = config->refresh_token_rolling;
  
  if (code_hash != NULL) {
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expiration_clause = o_strdup("> NOW()");
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expiration_clause = o_strdup("> NOW()");
    } else { // HOEL_DB_TYPE_SQLITE
      expiration_clause = o_strdup("> (strftime('%s','now'))");
    }
    j_query = json_pack("{sss[ss]s{sssssssis{ssss}}}",
                        "table",
                        GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE,
                        "columns",
                          "gpgc_username AS username",
                          "gpgc_id",
                        "where",
                          "gpgc_client_id",
                          client_id,
                          "gpgc_redirect_uri",
                          redirect_uri,
                          "gpgc_code_hash",
                          code_hash,
                          "gpgc_enabled",
                          1,
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
              if (json_object_get(j_element, "refresh-token-rolling") == json_false()) {
                rolling_refresh = 0;
              }
              if (json_object_get(j_element, "refresh-token-duration") != NULL && json_integer_value(json_object_get(j_element, "refresh-token-duration")) < maximum_duration) {
                maximum_duration = json_integer_value(json_object_get(j_element, "refresh-token-duration"));
              }
              json_array_append(json_object_get(json_array_get(j_result, 0), "scope"), j_element);
            }
            json_object_set_new(json_array_get(j_result, 0), "scope_list", json_string(scope_list));
            json_object_set_new(json_array_get(j_result, 0), "refresh-token-rolling", rolling_refresh?json_true():json_false());
            json_object_set_new(json_array_get(j_result, 0), "refresh-token-duration", json_integer(maximum_duration));
            j_return = json_pack("{sisO}", "result", G_OK, "code", json_array_get(j_result, 0));
            o_free(scope_list);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 validate_authorization_code - Error allocating resources for json_array()");
            j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 validate_authorization_code - Error executing j_query (2)");
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        json_decref(j_result_scope);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 validate_authorization_code - Error executing j_query (1)");
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 validate_authorization_code - Error glewlwyd_callback_generate_hash");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  o_free(code_hash);
  return j_return;
}

static json_t * validate_session_client_scope(struct _oauth2_config * config, const struct _u_request * request, const char * client_id, const char * scope) {
  json_t * j_session, * j_grant, * j_return, * j_scope_session, * j_scope_grant, * j_group, * j_scheme;
  const char * scope_session, * group;
  char * scope_filtered = NULL, * tmp;
  size_t index;
  json_int_t scopes_authorized = 0, scopes_granted = 0;
  int group_allowed;
  
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
                  if (!group_allowed && json_object_get(j_scheme, "scheme_authenticated") == json_true()) {
                    group_allowed = 1;
                  }
                }
                if (!group_allowed) {
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
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 validate_session_client_scope - Error glewlwyd_callback_get_client_granted_scopes");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_grant);
  } else if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 validate_session_client_scope - Error glewlwyd_callback_check_session_valid");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_session);
  return j_return;
}

static json_t * validate_refresh_token(struct _oauth2_config * config, const char * refresh_token) {
  json_t * j_return, * j_query, * j_result, * j_result_scope, * j_element;
  char * token_hash, * expires_at_clause;
  int res;
  size_t index;
  time_t now;

  if (refresh_token != NULL) {
    token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, refresh_token);
    if (token_hash != NULL) {
      time(&now);
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        expires_at_clause = msprintf("> FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("EXTRACT(TIMESTAMP FROM EPOCH %u)", now);
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("%u", (now));
      }
      j_query = json_pack("{sss[sssssssss]s{sssis{ssss}}}",
                          "table",
                          GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                          "columns",
                            "gpgr_id",
                            "gpgc_id",
                            "gpgr_username AS username",
                            "gpgr_client_id AS client_id",
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_issued_at) AS issued_at", "gpgr_issued_at AS issued_at", "EXTRACT(EPOCH FROM gpgr_issued_at) AS issued_at"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_expires_at) AS expired_at", "gpgr_expires_at AS expired_at", "EXTRACT(EPOCH FROM gpgr_expires_at) AS expired_at"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpgr_last_seen) AS last_seen", "gpgr_last_seen AS last_seen", "EXTRACT(EPOCH FROM gpgr_last_seen) AS last_seen"),
                            "gpgr_duration AS duration",
                            "gpgr_rolling_expiration",
                          "where",
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
          if (res == H_OK) {
            if (!json_object_set_new(json_array_get(j_result, 0), "scope", json_array())) {
              json_array_foreach(j_result_scope, index, j_element) {
                json_array_append(json_object_get(json_array_get(j_result, 0), "scope"), json_object_get(j_element, "scope"));
              }
              j_return = json_pack("{sisO}", "result", G_OK, "token", json_array_get(j_result, 0));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 validate_refresh_token - Error json_object_set_new");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            json_decref(j_result_scope);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 validate_refresh_token - Error executing j_query (2)");
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
          json_decref(j_query);
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 validate_refresh_token - Error executing j_query (1)");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 validate_refresh_token - Error glewlwyd_callback_generate_hash");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(token_hash);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

static json_t * refresh_token_list_get(struct _oauth2_config * config, const char * username, size_t offset, size_t limit, const char * sort) {
  json_t * j_query, * j_result, * j_return, * j_element;
  int res;
  size_t index;
  
  j_query = json_pack("{sss[ssssssssss]s{ss}sisi}",
                      "table",
                      GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN
                      "columns",
                        "gpgr_token_hash AS token_hash",
                        "gpgr_authorization_type AS authorization_type",
                        "gpgr_client_id AS client_id",
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(`gpgr_issued_at`) AS issued_at", "gpgr_issued_at AS issued_at", "EXTRACT(EPOCH FROM gpgr_issued_at) AS issued_at"),
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(`gpgr_expires_at`) AS expires_at", "gpgr_expires_at AS expires_at", "EXTRACT(EPOCH FROM gpgr_expires_at) AS expires_at"),
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(`gpgr_last_seen`) AS last_seen", "gpgr_last_seen AS last_seen", "EXTRACT(EPOCH FROM gpgr_last_seen) AS last_seen"),
                        "gpgr_rolling_expiration",
                        "gpgr_issued_for AS issued_for",
                        "gpgr_user_agent AS user_agent",
                        "gpgr_enabled",
                      "where",
                        "gpgr_username",
                        username,
                      "offset",
                      offset,
                      "limit",
                      limit);
  if (sort != NULL) {
    json_object_set_new(j_query, "order_by", json_string(sort));
  }
  res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      json_object_set(j_element, "rolling_expiration", (json_integer_value(json_object_get(j_element, "gpgr_rolling_expiration"))?json_true():json_false()));
      json_object_set(j_element, "enabled", (json_integer_value(json_object_get(j_element, "gpgr_enabled"))?json_true():json_false()));
      json_object_del(j_element, "gpgr_rolling_expiration");
      json_object_del(j_element, "gpgr_enabled");
    }
    j_return = json_pack("{sisO}", "result", G_OK, "refresh_token", j_result);
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_list_get - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

static int refresh_token_disable(struct _oauth2_config * config, const char * username, const char * token_hash) {
  json_t * j_query, * j_result;
  int res, ret;
  
  j_query = json_pack("{sss[ss]s{ssss}}",
                      "table",
                      GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN
                      "columns",
                        "gpgr_id",
                        "gpgr_enabled",
                      "where",
                        "gpgr_username",
                        username,
                        "gpgr_token_hash",
                        token_hash);
  res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      if (!json_integer_value(json_object_get(json_array_get(j_result, 0), "gpgr_enabled"))) {
        j_query = json_pack("{sss{si}s{ssss}}",
                            "table",
                            GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                            "set",
                              "gpgr_enabled",
                              0,
                            "where",
                              "gpgr_username",
                              username,
                              "gpgr_token_hash",
                              token_hash,
                              "gpgr_enabled");
        res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_list_get - Error executing j_query (2)");
          ret = G_ERROR_DB;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
    } else {
      ret = G_ERROR_NOT_FOUND;
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_list_get - Error executing j_query (1)");
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
    last_seen_clause = msprintf("EXTRACT(TIMESTAMP FROM EPOCH %u)", now);
  } else { // HOEL_DB_TYPE_SQLITE
    last_seen_clause = msprintf("%u", (now));
  }
  j_query = json_pack("{sss{s{ss}}s{sI}}",
                      "table",
                      GLEWLWYD_PLUGIN_OAUTH2_TABLE_REFRESH_TOKEN,
                      "set",
                        "gpgr_last_seen",
                          "raw",
                          last_seen_clause,
                      "where",
                        "gpgr_id",
                        gpgr_id);
  o_free(last_seen_clause);
  if (refresh_token_duration) {
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)refresh_token_duration));
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expires_at_clause = msprintf("EXTRACT(TIMESTAMP FROM EPOCH %u)", (now + (unsigned int)refresh_token_duration));
    } else { // HOEL_DB_TYPE_SQLITE
      expires_at_clause = msprintf("%u", (now + (unsigned int)refresh_token_duration));
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
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 update_refresh_token - Error executing j_query");
    ret = G_ERROR_DB;
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
  char * authorization_code = NULL, * redirect_url, * issued_for, * state_param = NULL, * state_encoded;
  json_t * j_session, * j_client = check_client_valid(config, u_map_get(request->map_url, "client_id"), request->auth_basic_user, request->auth_basic_password, u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "scope"), GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE);
  
  if (u_map_get(request->map_url, "state") != NULL) {
    state_encoded = url_encode(u_map_get(request->map_url, "state"));
    state_param = msprintf("&state=%s", state_encoded);
    o_free(state_encoded);
  } else {
    state_param = o_strdup("");
  }
  // Check if client is allowed to perform this request
  if (check_result_value(j_client, G_OK)) {
    // Client is allowed to use auth_code grant with this redirection_uri
    if (u_map_has_key(request->map_url, "g_continue")) {
      if (o_strlen(u_map_get(request->map_url, "scope"))) {
        j_session = validate_session_client_scope(config, request, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
        if (check_result_value(j_session, G_OK)) {
          if (json_object_get(json_object_get(j_session, "session"), "authorization_required") == json_false()) {
            // User has granted access to the cleaned scope list for this client
            // Generate code, generate the url and redirect to it
            issued_for = get_client_hostname(request);
            if (issued_for != NULL) {
              if (config->glewlwyd_config->glewlwyd_callback_trigger_session_used(config->glewlwyd_config, request, json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered"))) == G_OK) {
                authorization_code = generate_authorization_code(config, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered")), u_map_get(request->map_url, "redirect_uri"), issued_for, u_map_get_case(request->map_header, "user-agent"));
                redirect_url = msprintf("%s%scode=%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), authorization_code, state_param);
                ulfius_add_header_to_response(response, "Location", redirect_url);
                response->status = 302;
                o_free(redirect_url);
                o_free(authorization_code);
                o_free(issued_for);
              } else {
                redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
                y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_auth_code_grant - Error glewlwyd_callback_trigger_session_used");
                response->status = 302;
              }
            } else {
              redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_auth_code_grant - Error get_client_hostname");
              response->status = 302;
            }
          } else {
            // Redirect to login page
            redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
            response->status = 302;
          }
        } else if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
          // Redirect to login page
          redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          response->status = 302;
        } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
          // Scope is not allowed for this user
          response->status = 302;
          y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_auth_type_auth_code_grant - scope list '%s' is invalid for user '%s'", u_map_get(request->map_url, "scope"), json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")));
          redirect_url = msprintf("%s%serror=invalid_scope%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        } else {
          redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_auth_code_grant - Error validate_session_client_scope");
          response->status = 302;
        }
        json_decref(j_session);
      } else {
        // Scope is not allowed for this user
        y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_auth_type_auth_code_grant - scope list is missing or empty");
        response->status = 302;
        redirect_url = msprintf("%s%serror=invalid_scope%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), state_param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
    } else {
      // Redirect to login page
      redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
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
 * The second step of authentiation code
 * Validates if code, client_id and redirect_uri sent are valid, then returns a token set
 */
static int check_auth_type_access_token_request (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  const char * code = u_map_get(request->map_post_body, "code"), 
             * client_id = u_map_get(request->map_post_body, "client_id"),
             * redirect_uri = u_map_get(request->map_post_body, "redirect_uri");
  char * issued_for = get_client_hostname(request);
  json_t * j_code, * j_body, * j_refresh_token, * j_client = check_client_valid(config, client_id, request->auth_basic_user, request->auth_basic_password, redirect_uri, NULL, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE);
  time_t now;
  char * refresh_token = NULL, * access_token = NULL;
  
  if (code == NULL || client_id == NULL || redirect_uri == NULL) {
    response->status = 400;
  } else if (check_result_value(j_client, G_OK)) {
    j_code = validate_authorization_code(config, code, client_id, redirect_uri);
    if (check_result_value(j_code, G_OK)) {
      time(&now);
      if ((refresh_token = generate_refresh_token(config, client_id, json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, issued_for, json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), now)) != NULL) {
        j_refresh_token = serialize_refresh_token(config, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, json_integer_value(json_object_get(json_object_get(j_code, "code"), "gpgc_id")), json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), client_id, json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), now, json_integer_value(json_object_get(json_object_get(j_code, "code"), "refresh-token-duration")), json_object_get(json_object_get(j_code, "code"), "refresh-token-rolling")==json_true(), refresh_token, issued_for, u_map_get_case(request->map_header, "user-agent"));
        if (check_result_value(j_refresh_token, G_OK)) {
          if ((access_token = generate_access_token(config, json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), now)) != NULL) {
            if (serialize_access_token(config, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, json_integer_value(json_object_get(j_refresh_token, "gpgr_id")), json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), client_id, json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), now, issued_for, u_map_get_case(request->map_header, "user-agent")) == G_OK) {
              if (disable_authorization_code(config, json_integer_value(json_object_get(json_object_get(j_code, "code"), "gpgc_id"))) == G_OK) {
                j_body = json_pack("{sssssssisiss}",
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
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_access_token_request - Error disable_authorization_code");
                j_body = json_pack("{ss}", "error", "server_error");
                ulfius_set_json_body_response(response, 500, j_body);
                json_decref(j_body);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_access_token_request - Error serialize_access_token");
              j_body = json_pack("{ss}", "error", "server_error");
              ulfius_set_json_body_response(response, 500, j_body);
              json_decref(j_body);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_access_token_request - Error generate_access_token");
            j_body = json_pack("{ss}", "error", "server_error");
            ulfius_set_json_body_response(response, 500, j_body);
            json_decref(j_body);
          }
          o_free(access_token);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_access_token_request - Error serialize_refresh_token");
          j_body = json_pack("{ss}", "error", "server_error");
          ulfius_set_json_body_response(response, 500, j_body);
          json_decref(j_body);
        }
        json_decref(j_refresh_token);
        o_free(refresh_token);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_access_token_request - Error generate_refresh_token");
        j_body = json_pack("{ss}", "error", "server_error");
        ulfius_set_json_body_response(response, 500, j_body);
        json_decref(j_body);
      }
    } else {
      j_body = json_pack("{ss}", "error", "invalid_code");
      ulfius_set_json_body_response(response, 403, j_body);
      json_decref(j_body);
    }
    json_decref(j_code);
  } else {
    j_body = json_pack("{ss}", "error", "unauthorized_client");
    ulfius_set_json_body_response(response, 403, j_body);
    json_decref(j_body);
  }
  json_decref(j_client);
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
  char * redirect_url, * issued_for, * state_encoded = NULL, * state_param = NULL;
  json_t * j_session, * j_client = check_client_valid(config, u_map_get(request->map_url, "client_id"), request->auth_basic_user, request->auth_basic_password, u_map_get(request->map_url, "redirect_uri"), u_map_get(request->map_url, "scope"), GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE);
  char * access_token;
  time_t now;
  
  if (u_map_get(request->map_url, "state") != NULL) {
    state_encoded = url_encode(u_map_get(request->map_url, "state"));
    state_param = msprintf("&state=%s", state_encoded);
    o_free(state_encoded);
  } else {
    state_param = o_strdup("");
  }
  // Check if client is allowed to perform this request
  if (check_result_value(j_client, G_OK)) {
    // Client is allowed to use auth_code grant with this redirection_uri
    if (u_map_has_key(request->map_url, "g_continue")) {
      if (o_strlen(u_map_get(request->map_url, "scope"))) {
        j_session = validate_session_client_scope(config, request, u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
        if (check_result_value(j_session, G_OK)) {
          if (json_object_get(json_object_get(j_session, "session"), "authorization_required") == json_false()) {
            // User has granted access to the cleaned scope list for this client
            // Generate access token
            issued_for = get_client_hostname(request);
            if (issued_for != NULL) {
              time(&now);
              if ((access_token = generate_access_token(config, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered")), now)) != NULL) {
                if (serialize_access_token(config, GLEWLWYD_AUTHORIZATION_TYPE_IMPLICIT, 0, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered")), now, issued_for, u_map_get_case(request->map_header, "user-agent")) == G_OK) {
                  if (config->glewlwyd_config->glewlwyd_callback_trigger_session_used(config->glewlwyd_config, request, json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered"))) == G_OK) {
                    redirect_url = msprintf("%s%saccess_token=%s&token_type=bearer&expires_in=%d&scope=%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '#')!=NULL?"&":"#"), access_token, config->access_token_duration, json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered")), state_param);
                    ulfius_add_header_to_response(response, "Location", redirect_url);
                    o_free(redirect_url);
                    response->status = 302;
                  } else {
                    redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
                    ulfius_add_header_to_response(response, "Location", redirect_url);
                    o_free(redirect_url);
                    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_implicit_grant - Error glewlwyd_callback_trigger_session_used");
                    response->status = 302;
                  }
                } else {
                  redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
                  ulfius_add_header_to_response(response, "Location", redirect_url);
                  o_free(redirect_url);
                  y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_implicit_grant - Error serialize_access_token");
                  response->status = 302;
                }
              } else {
                redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
                y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_implicit_grant - Error generate_access_token");
                response->status = 302;
              }
              o_free(access_token);
            } else {
              redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_implicit_grant - Error get_client_hostname");
              response->status = 302;
            }
            o_free(issued_for);
          } else {
            // Redirect to login page
            redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
            response->status = 302;
          }
        } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
          // Scope is not allowed for this user
          y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_auth_type_implicit_grant - Scope list '%s' is not allowed for user '%s'", u_map_get(request->map_url, "scope"), json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")));
          response->status = 302;
          redirect_url = msprintf("%s%serror=invalid_scope%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        } else {
          redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_implicit_grant - Error validate_session_client_scope");
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
      redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
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
  json_t * j_user, * j_client, * j_refresh_token, * j_body;
  int ret = G_OK;
  const char * username = u_map_get(request->map_post_body, "username"),
             * password = u_map_get(request->map_post_body, "password"),
             * scope = u_map_get(request->map_post_body, "scope"),
             * client_id = NULL;
  char * issued_for = get_client_hostname(request),
       * refresh_token,
       * access_token;
  time_t now;
  
  if (scope == NULL || username == NULL || password == NULL || issued_for == NULL) {
    ret = G_ERROR_PARAM;
  } else if (request->auth_basic_user != NULL && request->auth_basic_password != NULL) {
    j_client = config->glewlwyd_config->glewlwyd_callback_check_client_valid(config->glewlwyd_config, request->auth_basic_user, request->auth_basic_password, NULL);
    if (check_result_value(j_client, G_OK) && json_object_get(json_object_get(j_client, "client"), "confidential") != json_true()) {
      ret = G_ERROR_PARAM;
    } else if (check_result_value(j_client, G_OK)) {
      client_id = request->auth_basic_user;
    } else if (check_result_value(j_client, G_ERROR_NOT_FOUND) || check_result_value(j_client, G_ERROR_UNAUTHORIZED)) {
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_resource_owner_pwd_cred - Error glewlwyd_callback_check_client_valid");
      ret = G_ERROR;
    }
    json_decref(j_client);
  }
  if (ret == G_OK) {
    j_user = config->glewlwyd_config->glewlwyd_callback_check_user_valid(config->glewlwyd_config, username, password, scope);
    if (check_result_value(j_user, G_OK)) {
      time(&now);
      if ((refresh_token = generate_refresh_token(config, client_id, username, GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, issued_for, json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")), now)) != NULL) {
        j_refresh_token = serialize_refresh_token(config, GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, 0, username, client_id, json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")), now, config->refresh_token_duration, config->refresh_token_rolling, refresh_token, issued_for, u_map_get_case(request->map_header, "user-agent"));
        if (check_result_value(j_refresh_token, G_OK)) {
          if ((access_token = generate_access_token(config, username, json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")), now)) != NULL) {
            if (serialize_access_token(config, GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, json_integer_value(json_object_get(j_refresh_token, "gpgr_id")), username, client_id, json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")), now, issued_for, u_map_get_case(request->map_header, "user-agent")) == G_OK) {
              j_body = json_pack("{sssssssisiss}",
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
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_resource_owner_pwd_cred - Error serialize_access_token");
              j_body = json_pack("{ss}", "error", "server_error");
              ulfius_set_json_body_response(response, 500, j_body);
              json_decref(j_body);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_resource_owner_pwd_cred - Error generate_access_token");
            j_body = json_pack("{ss}", "error", "server_error");
            ulfius_set_json_body_response(response, 500, j_body);
            json_decref(j_body);
          }
          o_free(access_token);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_resource_owner_pwd_cred - Error serialize_refresh_token");
          j_body = json_pack("{ss}", "error", "server_error");
          ulfius_set_json_body_response(response, 500, j_body);
          json_decref(j_body);
        }
        json_decref(j_refresh_token);
        o_free(refresh_token);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_resource_owner_pwd_cred - Error generate_refresh_token");
        j_body = json_pack("{ss}", "error", "server_error");
        ulfius_set_json_body_response(response, 500, j_body);
        json_decref(j_body);
      }
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND) || check_result_value(j_user, G_ERROR_UNAUTHORIZED)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_auth_type_resource_owner_pwd_cred - Error user '%s'", username);
      response->status = 403;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_resource_owner_pwd_cred - glewlwyd_callback_check_user_valid");
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
  json_t * j_client, * j_scope, * json_body;
  char ** scope_array, ** scope_allowed = NULL, * scope_joined, * access_token, * issued_for = get_client_hostname(request);
  size_t index;
  int i, i_scope_allowed = 0;
  time_t now;

  if (issued_for == NULL) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_client_credentials_grant  - Error get_client_hostname");
    response->status = 500;
  } else if (request->auth_basic_user != NULL && request->auth_basic_password != NULL && o_strlen(u_map_get(request->map_post_body, "scope")) > 0) {
    j_client = config->glewlwyd_config->glewlwyd_callback_check_client_valid(config->glewlwyd_config, request->auth_basic_user, request->auth_basic_password, u_map_get(request->map_post_body, "scope"));
    if (check_result_value(j_client, G_OK)) {
      if (split_string(u_map_get(request->map_post_body, "scope"), " ", &scope_array) > 0) {
        for (i=0; scope_array[i]!=NULL; i++) {
          json_array_foreach(json_object_get(json_object_get(j_client, "client"), "scope"), index, j_scope) {
            if (0 == o_strcmp(json_string_value(j_scope), scope_array[i])) {
              if (scope_allowed == NULL) {
                scope_allowed = o_malloc(2 * sizeof(char*));
              } else {
                scope_allowed = o_realloc(scope_allowed, (2 + i_scope_allowed) * sizeof(char*));
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
        } else {
          scope_joined = string_array_join((const char **)scope_allowed, " ");
          time(&now);
          if ((access_token = generate_client_access_token(config, request->auth_basic_user, issued_for, scope_joined, now)) != NULL) {
            if (serialize_access_token(config, GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS, 0, NULL, request->auth_basic_user, scope_joined, now, issued_for, u_map_get_case(request->map_header, "user-agent")) == G_OK) {
              json_body = json_pack("{sssssiss}",
                                    "access_token", access_token,
                                    "token_type", "bearer",
                                    "expires_in", config->access_token_duration,
                                    "scope", scope_joined);
              ulfius_set_json_body_response(response, 200, json_body);
              json_decref(json_body);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_client_credentials_grant - Error serialize_access_token");
              response->status = 500;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_client_credentials_grant - Error generate_client_access_token");
            response->status = 500;
          }
          o_free(access_token);
          o_free(scope_joined);
          o_free(scope_allowed);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 check_auth_type_client_credentials_grant - Error split_string");
        response->status = 500;
      }
      free_string_array(scope_array);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_auth_type_client_credentials_grant - Error client_d '%s' invalid", request->auth_basic_user);
      response->status = 403;
    }
    json_decref(j_client);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 check_auth_type_client_credentials_grant - Error invalid input parameters. client_id: '%s', scope: '%s'", request->auth_basic_user, u_map_get(request->map_post_body, "scope"));
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
  const char * refresh_token = u_map_get(request->map_post_body, "refresh_token");
  json_t * j_refresh, * json_body, * j_client;
  time_t now;
  char * access_token, * scope_joined = NULL, * issued_for;
  int has_error = 0, has_issues = 0;

  if (refresh_token != NULL && o_strlen(refresh_token)) {
    j_refresh = validate_refresh_token(config, refresh_token);
    if (check_result_value(j_refresh, G_OK)) {
      if (json_object_get(json_object_get(j_refresh, "token"), "client_id") != json_null()) {
        j_client = check_client_valid(config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), request->auth_basic_user, request->auth_basic_password, NULL, NULL, GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN);
        if (!check_result_value(j_client, G_OK)) {
          has_issues = 1;
        } else if (request->auth_basic_user == NULL && request->auth_basic_password == NULL && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 get_access_token_from_refresh - client '%s' is invalid or is not confidential", request->auth_basic_user);
          has_issues = 1;
        }
        json_decref(j_client);
      }
      time(&now);
      issued_for = get_client_hostname(request);
      scope_joined = join_json_string_array(json_object_get(json_object_get(j_refresh, "token"), "scope"), " ");
      if (scope_joined == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 get_access_token_from_refresh - Error join_json_string_array");
        has_error = 1;
      }
      if (update_refresh_token(config, json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "gpgr_id")), (json_object_get(json_object_get(j_refresh, "token"), "rolling_expiration") == json_true())?json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "duration")):0, 0, now) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 get_access_token_from_refresh - Error update_refresh_token");
        has_error = 1;
      }
      if (!has_error && !has_issues) {
        if ((access_token = generate_client_access_token(config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), issued_for, scope_joined, now)) != NULL) {
          if (serialize_access_token(config, GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS, 0, NULL, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), scope_joined, now, issued_for, u_map_get_case(request->map_header, "user-agent")) == G_OK) {
            json_body = json_pack("{sssssiss}",
                                  "access_token", access_token,
                                  "token_type", "bearer",
                                  "expires_in", config->access_token_duration,
                                  "scope", scope_joined);
            ulfius_set_json_body_response(response, 200, json_body);
            json_decref(json_body);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 get_access_token_from_refresh - Error serialize_access_token");
            response->status = 500;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 get_access_token_from_refresh - Error generate_client_access_token");
          response->status = 500;
        }
        o_free(access_token);
      } else if (has_issues) {
        response->status = 400;
      } else {
        response->status = 500;
      }
      o_free(issued_for);
    } else if (check_result_value(j_refresh, G_ERROR_NOT_FOUND)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 get_access_token_from_refresh - Error token not found");
      response->status = 400;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 get_access_token_from_refresh - Error validate_refresh_token");
      response->status = 500;
    }
    json_decref(j_refresh);
    o_free(scope_joined);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 get_access_token_from_refresh - Error token empty or missing");
    response->status = 400;
  }
  return U_CALLBACK_CONTINUE;
}

/**
 * Invalidate a refresh token
 */
static int delete_refresh_token (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  const char * refresh_token = u_map_get(request->map_post_body, "refresh_token");
  json_t * j_refresh, * j_client;
  time_t now;
  char * issued_for;
  int has_issues = 0;
  
  if (refresh_token != NULL && o_strlen(refresh_token)) {
    j_refresh = validate_refresh_token(config, refresh_token);
    if (check_result_value(j_refresh, G_OK)) {
      if (json_object_get(json_object_get(j_refresh, "token"), "client_id") != json_null()) {
        j_client = check_client_valid(config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), request->auth_basic_user, request->auth_basic_password, NULL, NULL, GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN);
        if (!check_result_value(j_client, G_OK)) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 delete_refresh_token - client '%s' is invalid", request->auth_basic_user);
          has_issues = 1;
        } else if (request->auth_basic_user == NULL && request->auth_basic_password == NULL && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 delete_refresh_token - client '%s' is invalid or is not confidential", request->auth_basic_user);
          has_issues = 1;
        }
        json_decref(j_client);
      }
      if (!has_issues) {
        time(&now);
        issued_for = get_client_hostname(request);
        if (update_refresh_token(config, json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "gpgr_id")), 0, 1, now) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 delete_refresh_token - Error update_refresh_token");
          response->status = 500;
        }
        o_free(issued_for);
      } else {
        response->status = 400;
      }
    } else if (check_result_value(j_refresh, G_ERROR_NOT_FOUND)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 delete_refresh_token - token invalid");
      response->status = 400;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 delete_refresh_token - Error validate_refresh_token");
      response->status = 500;
    }
    json_decref(j_refresh);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oauth2 delete_refresh_token - token missing or empty");
    response->status = 400;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_oauth2_authorization(const struct _u_request * request, struct _u_response * response, void * user_data) {
  const char * response_type = u_map_get(request->map_url, "response_type");
  int result = U_CALLBACK_CONTINUE;
  char * redirect_url, * state_encoded = NULL, * state_param = NULL;

  if (u_map_get(request->map_url, "state") != NULL) {
    state_encoded = url_encode(u_map_get(request->map_url, "state"));
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
  } else {
    response->status = 400;
  }
  return result;
}

static int callback_oauth2_get_profile(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  json_t * j_profile = config->glewlwyd_config->glewlwyd_plugin_callback_get_user_profile(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "username")));
  
  if (check_result_value(j_profile, G_OK)) {
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
    sort = msprintf("gpgr_%s", u_map_get(request->map_url, "sort"));
  }
  j_refresh_list = refresh_token_list_get(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), offset, limit, sort);
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
  
  if ((res = refresh_token_disable(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), u_map_get(request->map_url, "token_hash"))) == G_ERROR_NOT_FOUND) {
    response->status = 404;
  } else if (res != G_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_oauth2_disable_refresh_token - Error refresh_token_disable");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

static int callback_oauth2_clean(const struct _u_request * request, struct _u_response * response, void * user_data) {
  if (response->shared_data != NULL) {
    json_decref((json_t *)response->shared_data);
  }
  return U_CALLBACK_COMPLETE;
}

static int jwt_autocheck(struct _oauth2_config * config) {
  time_t now;
  char * token;
  jwt_t * jwt = NULL;
  int ret;
  
  time(&now);
  token = generate_access_token(config, GLEWLWYD_CHECK_JWT_USERNAME, GLEWLWYD_CHECK_JWT_SCOPE, now);
  if (token != NULL) {
    if (o_strcmp("sha", json_string_value(json_object_get(config->j_params, "jwt-type"))) == 0) {
      if (jwt_decode(&jwt, token, (const unsigned char *)json_string_value(json_object_get(config->j_params, "key")), json_string_length(json_object_get(config->j_params, "key")))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 jwt_autocheck - oauth2 - Error jwt_decode");
        ret = G_ERROR;
      } else if (jwt_get_alg(jwt) != jwt_get_alg(config->jwt_key)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 jwt_autocheck - oauth2 - Error algorithm don't match");
        ret = G_ERROR;
      } else {
        ret = G_OK;
      }
      jwt_free(jwt);
    } else {
      if (jwt_decode(&jwt, token, (const unsigned char *)json_string_value(json_object_get(config->j_params, "cert")), json_string_length(json_object_get(config->j_params, "cert")))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 jwt_autocheck - oauth2 - Error jwt_decode");
        ret = G_ERROR;
      } else if (jwt_get_alg(jwt) != jwt_get_alg(config->jwt_key)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 jwt_autocheck - oauth2 - Error algorithm don't match");
        ret = G_ERROR;
      } else {
        ret = G_OK;
      }
      jwt_free(jwt);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 jwt_autocheck - oauth2 - Error generate_access_token");
    ret = G_ERROR;
  }
  o_free(token);
  return ret;
}

static int check_parameters (json_t * j_params) {
  json_t * j_element;
  size_t index;
  
  if (j_params == NULL) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "url") == NULL || !json_is_string(json_object_get(j_params, "url")) || !json_string_length(json_object_get(j_params, "url"))) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "jwt-type") == NULL || !json_is_string(json_object_get(j_params, "jwt-type"))) {
    return G_ERROR_PARAM;
  } else if (0 != o_strcmp("rsa", json_string_value(json_object_get(j_params, "jwt-type"))) &&
             0 != o_strcmp("ecdsa", json_string_value(json_object_get(j_params, "jwt-type"))) &&
             0 != o_strcmp("sha", json_string_value(json_object_get(j_params, "jwt-type")))) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "jwt-key-size") == NULL || !json_is_string(json_object_get(j_params, "jwt-key-size"))) {
    return G_ERROR_PARAM;
  } else if (0 != o_strcmp("256", json_string_value(json_object_get(j_params, "jwt-key-size"))) &&
             0 != o_strcmp("384", json_string_value(json_object_get(j_params, "jwt-key-size"))) &&
             0 != o_strcmp("512", json_string_value(json_object_get(j_params, "jwt-key-size")))) {
    return G_ERROR_PARAM;
  } else if ((0 == o_strcmp("rsa", json_string_value(json_object_get(j_params, "jwt-type"))) ||
              0 == o_strcmp("ecdsa", json_string_value(json_object_get(j_params, "jwt-type")))) && 
             (json_object_get(j_params, "key") == NULL || json_object_get(j_params, "cert") == NULL ||
             !json_is_string(json_object_get(j_params, "key")) || !json_is_string(json_object_get(j_params, "cert")) || !json_string_length(json_object_get(j_params, "cert")))) {
    return G_ERROR_PARAM;
  } else if (0 == o_strcmp("sha", json_string_value(json_object_get(j_params, "jwt-type"))) &&
            (json_object_get(j_params, "key") == NULL || !json_is_string(json_object_get(j_params, "key")) || !json_string_length(json_object_get(j_params, "key")))) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "access-token-duration") == NULL || !json_is_integer(json_object_get(j_params, "access-token-duration")) || json_integer_value(json_object_get(j_params, "access-token-duration")) <= 0) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "refresh-token-duration") == NULL || !json_is_integer(json_object_get(j_params, "refresh-token-duration")) || json_integer_value(json_object_get(j_params, "refresh-token-duration")) <= 0) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "refresh-token-rolling") != NULL && !json_is_boolean(json_object_get(j_params, "refresh-token-rolling"))) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "auth-type-code-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-code-enabled"))) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "auth-type-implicit-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-implicit-enabled"))) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "auth-type-password-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-password-enabled"))) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "auth-type-client-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-client-enabled"))) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "auth-type-refresh-enabled") == NULL || !json_is_boolean(json_object_get(j_params, "auth-type-refresh-enabled"))) {
    return G_ERROR_PARAM;
  } else if (json_object_get(j_params, "scope") != NULL) {
    if (!json_is_array(json_object_get(j_params, "scope"))) {
      return G_ERROR_PARAM;
    } else {
      json_array_foreach(json_object_get(j_params, "scope"), index, j_element) {
        if (!json_is_object(j_element)) {
          return G_ERROR_PARAM;
        } else {
          if (json_object_get(j_element, "name") == NULL || !json_is_string(json_object_get(j_element, "name")) || !json_string_length(json_object_get(j_element, "name"))) {
            return G_ERROR_PARAM;
          } else if (json_object_get(j_element, "refresh-token-rolling") != NULL && !json_is_boolean(json_object_get(j_element, "refresh-token-rolling"))) {
            return G_ERROR_PARAM;
          } else if (json_object_get(j_element, "refresh-token-duration") != NULL && !json_is_integer(json_object_get(j_element, "refresh-token-duration"))) {
            return G_ERROR_PARAM;
          }
        }
      }
      return G_OK;
    }
  } else {
    return G_OK;
  }
}

json_t * plugin_module_load(struct config_plugin * config) {
  return json_pack("{si ss ss ss s{ s{ssso} s{sssos[sss]} s{sssos[sss]} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ss so s{ssso} s{ssso} }}}",
                   "result",
                   G_OK,
                   
                   "name",
                   "oauth2-glewlwyd",
                   
                   "display_name",
                   "Glewlwyd OAuth2 plugin",
                   
                   "description",
                   "Plugin for legacy Glewlwyd OAuth2 workflow",
                   
                   "parameters",
                     "url",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "jwt-type",
                       "type",
                       "list",
                       "mandatory",
                       json_true(),
                       "values",
                         "rsa",
                         "ecdsa",
                         "sha",
                         
                     "jwt-key-size",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       "values",
                         "256",
                         "384",
                         "512",
                         
                     "key",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "cert",
                       "type",
                       "string",
                       "mandatory",
                       json_true(),
                       
                     "access-token-duration",
                       "type",
                       "number",
                       "mandatory",
                       json_true(),
                       
                     "refresh-token-duration",
                       "type",
                       "number",
                       "mandatory",
                       json_true(),
                       
                     "refresh-token-rolling",
                       "type",
                       "boolean",
                       "default",
                       json_false(),
                       
                     "auth-type-code-enabled",
                       "type",
                       "boolean",
                       "mandatory",
                       json_true(),
                       
                     "auth-type-implicit-enabled",
                       "type",
                       "boolean",
                       "mandatory",
                       json_true(),
                       
                     "auth-type-password-enabled",
                       "type",
                       "boolean",
                       "mandatory",
                       json_true(),
                       
                     "auth-type-client-enabled",
                       "type",
                       "boolean",
                       "mandatory",
                       json_true(),
                       
                     "auth-type-refresh-enabled",
                       "type",
                       "boolean",
                       "mandatory",
                       json_true(),
                       
                     "scope",
                       "type",
                       "array",
                       "mandatory",
                       json_false(),
                       "format",
                         "type",
                         "string",
                         "mandatory",
                         json_true(),
                       "rolling-refresh",
                         "type",
                         "boolean",
                         "mandatory",
                         json_false());
}

int plugin_module_unload(struct config_plugin * config) {
  return G_OK;
}

int plugin_module_init(struct config_plugin * config, json_t * j_parameters, void ** cls) {
  int ret;
  const unsigned char * key;
  jwt_alg_t alg = 0;
  pthread_mutexattr_t mutexattr;
  
  y_log_message(Y_LOG_LEVEL_INFO, "Init plugin Glewlwyd Oauth2");
  *cls = o_malloc(sizeof(struct _oauth2_config));
  if (*cls != NULL) {
    pthread_mutexattr_init ( &mutexattr );
    pthread_mutexattr_settype( &mutexattr, PTHREAD_MUTEX_RECURSIVE );
    if (pthread_mutex_init(&((struct _oauth2_config *)*cls)->insert_lock, &mutexattr) != 0 || pthread_mutex_init(&((struct _oauth2_config *)*cls)->insert_lock, &mutexattr) != 0) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 plugin_module_init - Error initializing insert_lock or insert_cond");
      o_free(*cls);
      *cls = NULL;
      ret = G_ERROR;
    } else {
      ((struct _oauth2_config *)*cls)->jwt_key = NULL;
      ((struct _oauth2_config *)*cls)->j_params = json_incref(j_parameters);
      ((struct _oauth2_config *)*cls)->glewlwyd_config = config;
      ((struct _oauth2_config *)*cls)->glewlwyd_resource_config = o_malloc(sizeof(struct _glewlwyd_resource_config));
      if (((struct _oauth2_config *)*cls)->glewlwyd_resource_config != NULL) {
        ((struct _oauth2_config *)*cls)->glewlwyd_resource_config->method = G_METHOD_HEADER;
        ((struct _oauth2_config *)*cls)->glewlwyd_resource_config->oauth_scope = config->glewlwyd_config->profile_scope;
        ((struct _oauth2_config *)*cls)->glewlwyd_resource_config->realm = NULL;
        if (check_parameters(((struct _oauth2_config *)*cls)->j_params) == G_OK) {
          ((struct _oauth2_config *)*cls)->access_token_duration = json_integer_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "access-token-duration"));
          if (!((struct _oauth2_config *)*cls)->access_token_duration) {
            ((struct _oauth2_config *)*cls)->access_token_duration = GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT;
          }
          ((struct _oauth2_config *)*cls)->refresh_token_duration = json_integer_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "refresh-token-duration"));
          if (!((struct _oauth2_config *)*cls)->refresh_token_duration) {
            ((struct _oauth2_config *)*cls)->refresh_token_duration = GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT;
          }
          if (json_object_get(((struct _oauth2_config *)*cls)->j_params, "refresh-token-rolling") != NULL) {
            ((struct _oauth2_config *)*cls)->refresh_token_rolling = json_object_get(((struct _oauth2_config *)*cls)->j_params, "refresh-token-rolling")==json_true()?1:0;
          } else {
            ((struct _oauth2_config *)*cls)->refresh_token_rolling = 0;
          }
          ((struct _oauth2_config *)*cls)->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE] = json_object_get(((struct _oauth2_config *)*cls)->j_params, "auth-type-code-enabled")==json_true()?1:0;
          ((struct _oauth2_config *)*cls)->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_IMPLICIT] = json_object_get(((struct _oauth2_config *)*cls)->j_params, "auth-type-implicit-enabled")==json_true()?1:0;
          ((struct _oauth2_config *)*cls)->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS] = json_object_get(((struct _oauth2_config *)*cls)->j_params, "auth-type-password-enabled")==json_true()?1:0;
          ((struct _oauth2_config *)*cls)->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS] = json_object_get(((struct _oauth2_config *)*cls)->j_params, "auth-type-client-enabled")==json_true()?1:0;
          ((struct _oauth2_config *)*cls)->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN] = json_object_get(((struct _oauth2_config *)*cls)->j_params, "auth-type-refresh-enabled")==json_true()?1:0;
          if (!jwt_new(&((struct _oauth2_config *)*cls)->jwt_key)) {
            if (0 == o_strcmp("rsa", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "jwt-type")))) {
              key = (const unsigned char *)json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "key"));
              if (0 == o_strcmp("256", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "jwt-key-size")))) {
                alg = JWT_ALG_RS256;
              } else if (0 == o_strcmp("256", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "jwt-key-size")))) {
                alg = JWT_ALG_RS384;
              } else { // 512
                alg = JWT_ALG_RS512;
              }
            } else if (0 == o_strcmp("ecdsa", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "jwt-type")))) {
              key = (const unsigned char *)json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "key"));
              if (0 == o_strcmp("256", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "jwt-key-size")))) {
                alg = JWT_ALG_ES256;
              } else if (0 == o_strcmp("256", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "jwt-key-size")))) {
                alg = JWT_ALG_ES384;
              } else { // 512
                alg = JWT_ALG_ES512;
              }
            } else { // SHA
              key = (const unsigned char *)json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "key"));
              if (0 == o_strcmp("256", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "jwt-key-size")))) {
                alg = JWT_ALG_HS256;
              } else if (0 == o_strcmp("256", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "jwt-key-size")))) {
                alg = JWT_ALG_HS384;
              } else { // 512
                alg = JWT_ALG_HS512;
              }
            }
            if (jwt_set_alg(((struct _oauth2_config *)*cls)->jwt_key, alg, key, o_strlen((const char *)key))) {
              json_decref(((struct _oauth2_config *)*cls)->j_params);
              jwt_free(((struct _oauth2_config *)*cls)->jwt_key);
              o_free(*cls);
              *cls = NULL;
              y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 protocol_init - oauth2 - Error allocating resources for jwt_key");
              ret = G_ERROR_MEMORY;
            } else {
              if (jwt_autocheck(((struct _oauth2_config *)*cls)) != G_OK) {
                json_decref(((struct _oauth2_config *)*cls)->j_params);
                jwt_free(((struct _oauth2_config *)*cls)->jwt_key);
                o_free(*cls);
                *cls = NULL;
                y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 protocol_init - oauth2 - Error jwt_autocheck");
                ret = G_ERROR_MEMORY;
              } else {
                if (0 == o_strcmp("sha", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "jwt-type")))) {
                  ((struct _oauth2_config *)*cls)->glewlwyd_resource_config->jwt_decode_key = o_strdup(json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "key")));
                } else {
                  ((struct _oauth2_config *)*cls)->glewlwyd_resource_config->jwt_decode_key = o_strdup(json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "cert")));
                }
                ((struct _oauth2_config *)*cls)->glewlwyd_resource_config->jwt_alg = alg;
                // Add endpoints
                y_log_message(Y_LOG_LEVEL_DEBUG, "Add endpoints with plugin prefix %s", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "url")));
                if (config->glewlwyd_callback_add_plugin_endpoint(config, "GET", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "url")), "auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_authorization, (void*)*cls) != G_OK || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "POST", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "url")), "token/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_token, (void*)*cls) || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "*", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "url")), "profile/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_glewlwyd_access_token, ((struct _oauth2_config *)*cls)->glewlwyd_resource_config) || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "GET", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "url")), "profile/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_get_profile, (void*)*cls) || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "GET", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "url")), "profile/token/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_refresh_token_list_get, (void*)*cls) || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "DELETE", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "url")), "profile/token/:token_hash", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_disable_refresh_token, (void*)*cls) || 
                   config->glewlwyd_callback_add_plugin_endpoint(config, "*", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "url")), "profile/*", GLEWLWYD_CALLBACK_PRIORITY_CLOSE, &callback_oauth2_clean, NULL)) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 protocol_init - oauth2 - Error adding endpoints");
                  ret = G_ERROR;
                } else {
                  ret = G_OK;
                }
              }
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 protocol_init - oauth2 - Error allocating resources for jwt_key");
            json_decref(((struct _oauth2_config *)*cls)->j_params);
            o_free(*cls);
            *cls = NULL;
            ret = G_ERROR_MEMORY;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 protocol_init - oauth2 - Error parameters");
          o_free(*cls);
          *cls = NULL;
          ret = G_ERROR_MEMORY;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 plugin_module_init - Error initializing glewlwyd_resource_config");
        o_free(*cls);
        *cls = NULL;
        ret = G_ERROR;
      }
    }
    pthread_mutexattr_destroy(&mutexattr);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oauth2 protocol_init - oauth2 - Error allocating resources for cls");
    o_free(*cls);
    *cls = NULL;
    ret = G_ERROR_MEMORY;
  }
  return ret;
}

int plugin_module_close(struct config_plugin * config, void * cls) {
  if (cls != NULL) {
    pthread_mutex_destroy(&((struct _oauth2_config *)cls)->insert_lock);
    jwt_free(((struct _oauth2_config *)cls)->jwt_key);
    json_decref(((struct _oauth2_config *)cls)->j_params);
    o_free(((struct _oauth2_config *)cls)->glewlwyd_resource_config->jwt_decode_key);
    o_free(((struct _oauth2_config *)cls)->glewlwyd_resource_config);
    o_free(cls);
  }
  return G_OK;
}

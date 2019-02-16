/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * Mock user module
 *
 * Copyright 2018 Nicolas Mora <mail@babelouest.org>
 *
 * Licence MIT
 *
 */

#include <string.h>
#include <jansson.h>
#include <jwt.h>
#include <yder.h>
#include <orcania.h>
#include <ulfius.h>
#include "../glewlwyd-common.h"

#define OAUTH2_SALT_LENGTH 16

#define GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT 3600
#define GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT 1209600
#define GLEWLWYD_CODE_EXP_DEFAULT 600

#define GLEWLWYD_CHECK_JWT_USERNAME "myrddin"
#define GLEWLWYD_CHECK_JWT_SCOPE    "caledonia"

#define GLEWLWYD_PLUGIN_OAUTH2_TABLE_CODE "gpg_code"

// Authorization types available
#define GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE                  0
#define GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT                            1
#define GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS 2
#define GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS                  3
#define GLEWLWYD_AUHORIZATION_TYPE_REFRESH_TOKEN                       4

struct _oauth2_config {
  struct config_plugin * glewlwyd_config;
  jwt_t * jwt_key;
  json_t * j_params;
  unsigned long access_token_duration;
  unsigned long refresh_token_duration;
  unsigned short int auth_type_enabled[5];
  unsigned short int use_scope;
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
      }
    }
  }
  
  return query;
}

static int is_authorization_type_enabled(struct _oauth2_config * config, uint authorization_type) {
  return (authorization_type <= 4)?config->auth_type_enabled[authorization_type]:0;
}

static int is_client_valid(struct _oauth2_config * config, const char * client_id, const char * client_header_login, const char * client_header_password, const char * redirect_uri, unsigned short authorization_type) {
  json_t * j_client, * j_element;
  int ret, uri_found, authorization_type_enabled;
  size_t index;
  
  if (client_id == NULL || redirect_uri == NULL) {
    return G_ERROR_PARAM;
  } else if (client_header_login != NULL) {
    if (0 != o_strcmp(client_header_login, client_id)) {
      return G_ERROR_PARAM;
    } else if (client_header_login == NULL) {
      return G_ERROR_PARAM;
    }
  }
  j_client = config->glewlwyd_config->glewlwyd_callback_is_client_valid(config->glewlwyd_config, client_id, client_header_password, NULL);
  if (check_result_value(j_client, G_OK)) {
    uri_found = 0;
    json_array_foreach(json_object_get(json_object_get(j_client, "client"), "redirect_uri"), index, j_element) {
      if (0 == o_strcmp(json_string_value(j_element), redirect_uri)) {
        uri_found = 1;
      }
    }
    
    authorization_type_enabled = 0;
    json_array_foreach(json_object_get(json_object_get(j_client, "client"), "authorization_type"), index, j_element) {
      if (authorization_type == GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE && 0 == o_strcmp(json_string_value(j_element), "code")) {
        authorization_type_enabled = 1;
      } else if (authorization_type == GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT && 0 == o_strcmp(json_string_value(j_element), "token")) {
        authorization_type_enabled = 1;
      } else if (authorization_type == GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS && 0 == o_strcmp(json_string_value(j_element), "client_credentials")) {
        authorization_type_enabled = 1;
      }
    }
    if (uri_found && authorization_type_enabled) {
      ret = G_OK;
    } else {
      ret = G_ERROR_PARAM;
    }
  } else {
    ret = G_ERROR_UNAUTHORIZED;
  }
  json_decref(j_client);
  return ret;
}

static char * generate_authorization_code(struct _oauth2_config * config, const char * username, const char * client_id, json_t * j_scope_list, const char * redirect_uri) {
  char * scope_list = NULL, * code = NULL, * code_hash = NULL, * expiration_clause;
  json_t * j_query;
  int res;
  time_t now;

  if (j_scope_list != NULL && json_array_size(j_scope_list)) {
    scope_list = join_json_string_array(j_scope_list, " ");
    if (scope_list == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error join_json_string_array");
      return NULL;
    }
  }
  code = o_malloc(33*sizeof(char));
  if (code != NULL) {
    if (rand_string(code, 32) != NULL) {
      code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code);
      if (code_hash != NULL) {
        time(&now);
        expiration_clause = config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB?msprintf("FROM_UNIXTIME(%u)", (now + GLEWLWYD_CODE_EXP_DEFAULT )):msprintf("%u", (now + GLEWLWYD_CODE_EXP_DEFAULT ));
        j_query = json_pack("{sss{sssssssss{ss}}}",
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
                              "gpgc_expiration",
                                "raw",
                                expiration_clause);
        if (scope_list != NULL) {
          json_object_set_new(json_object_get(j_query, "values"), "gpgc_scope", json_string(scope_list));
        }
        o_free(expiration_clause);
        res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
        json_decref(j_query);
        if (res != H_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error executing j_query");
          o_free(code);
          code = NULL;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error glewlwyd_callback_generate_hash");
        o_free(code);
        code = NULL;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error rand_string");
      o_free(code);
      code = NULL;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_authorization_code - Error allocating resources for code");
  }

  o_free(scope_list);
  o_free(code_hash);
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

/**
 * The most used authorization type: if client is authorized and has granted access to scope, 
 * glewlwyd redirects to redirect_uri with a code in the uri
 * If necessary, two intermediate steps can be used: login page and grant access page
 */
static int check_auth_type_auth_code_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  char * authorization_code = NULL, * redirect_url, * scope_allowed;
  json_t * j_session, * j_grant, * j_element, * j_scope_granted;
  size_t index;
  
  // Check if client is allowed to perform this request
  if (is_client_valid(config, u_map_get(request->map_url, "client_id"), request->auth_basic_user, request->auth_basic_password, u_map_get(request->map_url, "redirect_uri"), GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE) == G_OK) {
    // Client is allowed to use auth_code grant with this redirection_uri
    if (config->use_scope) {
      if (u_map_get(request->map_url, "scope") != NULL) {
        j_session = config->glewlwyd_config->glewlwyd_callback_is_session_valid(config->glewlwyd_config, request, u_map_get(request->map_url, "scope"));
        if (check_result_value(j_session, G_OK)) {
          // Check that user has granted at least one scope for this client
          scope_allowed = join_json_string_array(json_object_get(json_object_get(j_session, "session"), "scope"), " ");
          j_grant = config->glewlwyd_config->glewlwyd_callback_get_client_granted_scopes(config->glewlwyd_config, u_map_get(request->map_url, "client_id"), json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), scope_allowed);
          if (check_result_value(j_grant, G_OK)) {
            j_scope_granted = json_array();
            if (j_scope_granted != NULL) {
              json_array_foreach(json_object_get(json_object_get(j_grant, "grant"), "scope"), index, j_element) {
                if (json_object_get(j_element, "granted") == json_true()) {
                  json_array_append(j_scope_granted, json_object_get(j_element, "name"));
                }
              }
              if (json_array_size(j_scope_granted)) {
                // User has granted access to the cleaned scope list for this client
                // Generate code, generate the url and redirect to it
                authorization_code = generate_authorization_code(config, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), u_map_get(request->map_url, "client_id"), json_object_get(json_object_get(j_session, "session"), "scope"), u_map_get(request->map_url, "redirect_uri"));
                redirect_url = msprintf("%s%scode=%s%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), authorization_code, (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
                o_free(authorization_code);
                response->status = 302;
              } else {
                // Redirect to login page
                redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
                response->status = 302;
              }
            } else {
              redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
              y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_auth_code_grant - Error allocating resources for j_scope_granted");
              response->status = 500;
            }
            json_decref(j_scope_granted);
          } else {
            redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
            y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_auth_code_grant - Error glewlwyd_callback_get_client_granted_scopes");
            response->status = 500;
          }
          o_free(scope_allowed);
          json_decref(j_grant);
        } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
          // Redirect to login page
          redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          response->status = 302;
        } else {
          redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_auth_code_grant - Error glewlwyd_callback_is_session_valid");
          response->status = 500;
        }
        json_decref(j_session);
      } else {
        // Scope is not allowed for this user
        response->status = 302;
        redirect_url = msprintf("%s%serror=invalid_scope%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):"")); ulfius_add_header_to_response(response, "Location", redirect_url);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
    } else {
      j_session = config->glewlwyd_config->glewlwyd_callback_is_session_valid(config->glewlwyd_config, request, NULL);
      if (check_result_value(j_session, G_OK)) {
        // User has granted access to the cleaned scope list for this client
        // Generate code, generate the url and redirect to it
        authorization_code = generate_authorization_code(config, json_string_value(json_object_get(json_object_get(j_session, "session"), "username")), u_map_get(request->map_url, "client_id"), NULL, u_map_get(request->map_url, "redirect_uri"));
        redirect_url = msprintf("%s%scode=%s%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), authorization_code, (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
        o_free(authorization_code);
        response->status = 302;
      } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
        // Redirect to login page
        redirect_url = get_login_url(config, request, "auth", u_map_get(request->map_url, "client_id"), u_map_get(request->map_url, "scope"));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
        response->status = 302;
      } else {
        redirect_url = msprintf("%s%sserver_error", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
        y_log_message(Y_LOG_LEVEL_ERROR, "check_auth_type_auth_code_grant - Error glewlwyd_callback_is_session_valid");
        response->status = 500;
      }
      json_decref(j_session);
    }
  } else {
    // client is not authorized with this redirect_uri
    response->status = 302;
    redirect_url = msprintf("%s%serror=unauthorized_client%s%s", u_map_get(request->map_url, "redirect_uri"), (o_strchr(u_map_get(request->map_url, "redirect_uri"), '?')!=NULL?"&":"?"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
    ulfius_add_header_to_response(response, "Location", redirect_url);
    o_free(redirect_url);
  }
  return U_CALLBACK_CONTINUE;
}

/**
 * TODO
 */
static int check_auth_type_access_token_request (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_CALLBACK_ERROR;
}

/**
 * TODO
 */
static int check_auth_type_implicit_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_CALLBACK_ERROR;
}

/**
 * TODO
 */
static int check_auth_type_resource_owner_pwd_cred (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_CALLBACK_ERROR;
}

/**
 * TODO
 */
static int check_auth_type_client_credentials_grant (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_CALLBACK_ERROR;
}

/**
 * TODO
 */
static int get_access_token_from_refresh (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_CALLBACK_ERROR;
}

/**
 * TODO
 */
static int delete_refresh_token (const struct _u_request * request, struct _u_response * response, void * user_data) {
  return U_CALLBACK_ERROR;
}

static int callback_oauth2_authorization(const struct _u_request * request, struct _u_response * response, void * user_data) {
  const char * response_type = u_map_get(request->map_url, "response_type");
  int result = U_CALLBACK_CONTINUE;
  char * redirect_url;

  if (0 == o_strcmp("code", response_type)) {
    if (is_authorization_type_enabled((struct _oauth2_config *)user_data, GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE) && u_map_get(request->map_url, "redirect_uri") != NULL) {
      result = check_auth_type_auth_code_grant(request, response, user_data);
    } else {
      if (u_map_get(request->map_url, "redirect_uri") != NULL) {
        response->status = 302;
        redirect_url = msprintf("%s#error=unsupported_response_type%s%s", u_map_get(request->map_url, "redirect_uri"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      } else {
        response->status = 403;
      }
    }
  } else if (0 == o_strcmp("token", response_type)) {
    if (is_authorization_type_enabled((struct _oauth2_config *)user_data, GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT) && u_map_get(request->map_url, "redirect_uri") != NULL) {
      result = check_auth_type_implicit_grant(request, response, user_data);
    } else {
      if (u_map_get(request->map_url, "redirect_uri") != NULL) {
        response->status = 302;
        redirect_url = msprintf("%s#error=unsupported_response_type%s%s", u_map_get(request->map_url, "redirect_uri"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      } else {
        response->status = 403;
      }
    }
  } else {
    if (u_map_get(request->map_url, "redirect_uri") != NULL) {
      response->status = 302;
      redirect_url = msprintf("%s#error=unsupported_response_type%s%s", u_map_get(request->map_url, "redirect_uri"), (u_map_get(request->map_url, "state")!=NULL?"&state=":""), (u_map_get(request->map_url, "state")!=NULL?u_map_get(request->map_url, "state"):""));
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
    } else {
      response->status = 403;
    }
  }

  return result;
}

static int callback_oauth2_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oauth2_config * config = (struct _oauth2_config *)user_data;
  const char * grant_type = u_map_get(request->map_post_body, "grant_type");
  int result = U_CALLBACK_CONTINUE;

  if (0 == o_strcmp("authorization_code", grant_type)) {
    if (is_authorization_type_enabled(config, GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE)) {
      result = check_auth_type_access_token_request(request, response, user_data);
    } else {
      response->status = 403;
    }
  } else {
    response->status = 400;
  }
  return result;
}

static char * generate_access_token(struct _oauth2_config * config, const char * username, const char * scope_list) {
  char salt[OAUTH2_SALT_LENGTH + 1] = {0};
  jwt_t * jwt = NULL;
  time_t now;
  char * token = NULL;
  
  if ((jwt = jwt_dup(config->jwt_key)) != NULL) {
    time(&now);
    rand_string(salt, OAUTH2_SALT_LENGTH);
    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "salt", salt);
    jwt_add_grant(jwt, "type", "access_token");
    jwt_add_grant_int(jwt, "iat", now);
    jwt_add_grant_int(jwt, "expires_in", config->refresh_token_duration);
    if (scope_list != NULL) {
      jwt_add_grant(jwt, "scope", scope_list);
    }
    token = jwt_encode_str(jwt);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_access_token - oauth2 - Error jwt_encode_str");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_access_token - oauth2 - Error jwt_dup");
  }
  jwt_free(jwt);
  return token;
}

static int jwt_autocheck(struct _oauth2_config * config) {
  char * token = generate_access_token(config, GLEWLWYD_CHECK_JWT_USERNAME, GLEWLWYD_CHECK_JWT_SCOPE);
  jwt_t * jwt = NULL;
  int ret;
  
  if (token != NULL) {
    if (o_strcmp("sha", json_string_value(json_object_get(config->j_params, "jwt-type"))) == 0) {
      if (jwt_decode(&jwt, token, (const unsigned char *)json_string_value(json_object_get(config->j_params, "key")), json_string_length(json_object_get(config->j_params, "key")))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "jwt_autocheck - oauth2 - Error jwt_decode");
        ret = G_ERROR;
      } else if (jwt_get_alg(jwt) != jwt_get_alg(config->jwt_key)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "jwt_autocheck - oauth2 - Error algorithm don't match");
        ret = G_ERROR;
      } else {
        ret = G_OK;
      }
      jwt_free(jwt);
    } else {
      if (jwt_decode(&jwt, token, (const unsigned char *)json_string_value(json_object_get(config->j_params, "cert")), json_string_length(json_object_get(config->j_params, "cert")))) {
        y_log_message(Y_LOG_LEVEL_ERROR, "jwt_autocheck - oauth2 - Error jwt_decode");
        ret = G_ERROR;
      } else if (jwt_get_alg(jwt) != jwt_get_alg(config->jwt_key)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "jwt_autocheck - oauth2 - Error algorithm don't match");
        ret = G_ERROR;
      } else {
        ret = G_OK;
      }
      jwt_free(jwt);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "jwt_autocheck - oauth2 - Error generate_access_token");
    ret = G_ERROR;
  }
  free(token);
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
  } else if (json_object_get(j_params, "use-scope") == NULL || !json_is_boolean(json_object_get(j_params, "use-scope"))) {
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
          } else if (json_object_get(j_element, "rolling-refresh") != NULL && !json_is_boolean(json_object_get(j_element, "rolling-refresh"))) {
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

int plugin_module_load(struct config_plugin * config, char ** name, char ** parameters) {
  int ret = G_OK;
  if (name != NULL && parameters != NULL) {
    y_log_message(Y_LOG_LEVEL_INFO, "Load plugin Glewlwyd Oauth2");
    *name = o_strdup("oauth2-glewlwyd");
    *parameters = o_strdup("{\"id\":{\"type\":\"string\",\"mandatory\":true},"\
                            "\"url\":{\"type\":\"string\",\"mandatory\":true},"\
                            "\"jwt-type\":{\"type\":\"list\",\"values\":[\"rsa\",\"ecdsa\",\"sha\"],\"mandatory\":true},"\
                            "\"jwt-key-size\":{\"type\":\"list\",\"values\":[\"256\",\"384\",\"512\"],\"mandatory\":true},"\
                            "\"key\":{\"type\":\"string\",\"mandatory\":false},"\
                            "\"cert\":{\"type\":\"string\",\"mandatory\":false},"\
                            "\"access-token-duration\":{\"type\":\"number\",\"mandatory\":true},"\
                            "\"refresh-token-duration\":{\"type\":\"number\",\"mandatory\":true},"\
                            "\"auth-type-code-enabled\":{\"type\":\"boolean\",\"mandatory\":true},"\
                            "\"auth-type-implicit-enabled\":{\"type\":\"boolean\",\"mandatory\":true},"\
                            "\"auth-type-password-enabled\":{\"type\":\"boolean\",\"mandatory\":true},"\
                            "\"auth-type-client-enabled\":{\"type\":\"boolean\",\"mandatory\":true},"\
                            "\"auth-type-refresh-enabled\":{\"type\":\"boolean\",\"mandatory\":true},"\
                            "\"use-scope\":{\"type\":\"boolean\",\"mandatory\":true},"\
                            "\"scope\":{\"type\":\"array\",\"mandatory\":false,\"format\":{\"name\":{\"type\":\"string\",\"mandatory\":true},"\
                                                                                          "\"rolling-refresh\":{\"type\":\"boolean\",\"mandatory\":false}}}}");
  } else {
    ret = G_ERROR;
  }
  return ret;
}

int plugin_module_unload(struct config_plugin * config) {
  return G_OK;
}

int plugin_module_init(struct config_plugin * config, const char * parameters, void ** cls) {
  int ret;
  const unsigned char * key;
  jwt_alg_t alg = 0;
  
  y_log_message(Y_LOG_LEVEL_INFO, "Init plugin Glewlwyd Oauth2");
  *cls = o_malloc(sizeof(struct _oauth2_config));
  if (*cls != NULL) {
    ((struct _oauth2_config *)*cls)->jwt_key = NULL;
    ((struct _oauth2_config *)*cls)->j_params = json_loads(parameters, JSON_DECODE_ANY, 0);
    ((struct _oauth2_config *)*cls)->glewlwyd_config = config;
    if (check_parameters(((struct _oauth2_config *)*cls)->j_params) == G_OK) {
      ((struct _oauth2_config *)*cls)->access_token_duration = json_integer_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "access-token-duration"));
      if (!((struct _oauth2_config *)*cls)->access_token_duration) {
        ((struct _oauth2_config *)*cls)->access_token_duration = GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT;
      }
      ((struct _oauth2_config *)*cls)->refresh_token_duration = json_integer_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "refresh-token-duration"));
      if (!((struct _oauth2_config *)*cls)->refresh_token_duration) {
        ((struct _oauth2_config *)*cls)->refresh_token_duration = GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT;
      }
      ((struct _oauth2_config *)*cls)->auth_type_enabled[GLEWLWYD_AUHORIZATION_TYPE_AUTHORIZATION_CODE] = json_object_get(((struct _oauth2_config *)*cls)->j_params, "auth-type-code-enabled")==json_true()?1:0;
      ((struct _oauth2_config *)*cls)->auth_type_enabled[GLEWLWYD_AUHORIZATION_TYPE_IMPLICIT] = json_object_get(((struct _oauth2_config *)*cls)->j_params, "auth-type-implicit-enabled")==json_true()?1:0;
      ((struct _oauth2_config *)*cls)->auth_type_enabled[GLEWLWYD_AUHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS] = json_object_get(((struct _oauth2_config *)*cls)->j_params, "auth-type-password-enabled")==json_true()?1:0;
      ((struct _oauth2_config *)*cls)->auth_type_enabled[GLEWLWYD_AUHORIZATION_TYPE_CLIENT_CREDENTIALS] = json_object_get(((struct _oauth2_config *)*cls)->j_params, "auth-type-client-enabled")==json_true()?1:0;
      ((struct _oauth2_config *)*cls)->auth_type_enabled[GLEWLWYD_AUHORIZATION_TYPE_REFRESH_TOKEN] = json_object_get(((struct _oauth2_config *)*cls)->j_params, "auth-type-refresh-enabled")==json_true()?1:0;
      ((struct _oauth2_config *)*cls)->use_scope = json_object_get(((struct _oauth2_config *)*cls)->j_params, "use-scope")==json_true()?1:0;
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
          y_log_message(Y_LOG_LEVEL_ERROR, "protocol_init - oauth2 - Error allocating resources for jwt_key");
          ret = G_ERROR_MEMORY;
        } else {
          if (jwt_autocheck(((struct _oauth2_config *)*cls)) != G_OK) {
            json_decref(((struct _oauth2_config *)*cls)->j_params);
            jwt_free(((struct _oauth2_config *)*cls)->jwt_key);
            o_free(*cls);
            *cls = NULL;
            y_log_message(Y_LOG_LEVEL_ERROR, "protocol_init - oauth2 - Error jwt_autocheck");
            ret = G_ERROR_MEMORY;
          } else {
            // Add endpoints
            y_log_message(Y_LOG_LEVEL_DEBUG, "Add endpoints with plugin prefix %s", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "url")));
            if (config->glewlwyd_callback_add_plugin_endpoint(config, "GET", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "url")), "auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_authorization, (void*)*cls) != G_OK || 
               config->glewlwyd_callback_add_plugin_endpoint(config, "POST", json_string_value(json_object_get(((struct _oauth2_config *)*cls)->j_params, "url")), "token/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oauth2_token, (void*)*cls)) {
              y_log_message(Y_LOG_LEVEL_ERROR, "protocol_init - oauth2 - Error adding endpoints");
              ret = G_ERROR;
            } else {
              ret = G_OK;
            }
          }
        }
      } else {
        json_decref(((struct _oauth2_config *)*cls)->j_params);
        o_free(*cls);
        *cls = NULL;
        y_log_message(Y_LOG_LEVEL_ERROR, "protocol_init - oauth2 - Error allocating resources for jwt_key");
        ret = G_ERROR_MEMORY;
      }
    } else {
      o_free(*cls);
      *cls = NULL;
      y_log_message(Y_LOG_LEVEL_ERROR, "protocol_init - oauth2 - Error parameters");
      ret = G_ERROR_MEMORY;
    }
  } else {
    o_free(*cls);
    *cls = NULL;
    y_log_message(Y_LOG_LEVEL_ERROR, "protocol_init - oauth2 - Error allocating resources for cls");
    ret = G_ERROR_MEMORY;
  }
  return ret;
}

int plugin_module_close(struct config_plugin * config, void * cls) {
  if (cls != NULL) {
    jwt_free(((struct _oauth2_config *)cls)->jwt_key);
    json_decref(((struct _oauth2_config *)cls)->j_params);
    o_free(cls);
  }
  return G_OK;
}

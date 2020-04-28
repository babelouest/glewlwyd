/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * OpenID Connect Core plugin
 * 
 * Copyright 2019 Nicolas Mora <mail@babelouest.org>
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
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <jansson.h>
#include <yder.h>
#include <orcania.h>
#include <ulfius.h>
#include <rhonabwy.h>
#include "../glewlwyd-common.h"
#include "../../docs/resources/ulfius/oidc_resource.h"

#define OIDC_SALT_LENGTH 16
#define OIDC_JTI_LENGTH 32
#define OIDC_REFRESH_TOKEN_LENGTH 128

#define GLEWLWYD_ACCESS_TOKEN_EXP_DEFAULT 3600
#define GLEWLWYD_REFRESH_TOKEN_EXP_DEFAULT 1209600
#define GLEWLWYD_CODE_EXP_DEFAULT 600
#define GLEWLWYD_CODE_CHALLENGE_MAX_LENGTH 128
#define GLEWLWYD_CODE_CHALLENGE_S256_PREFIX "{SHA256}"

#define GLEWLWYD_CHECK_JWT_USERNAME "myrddin"
#define GLEWLWYD_CHECK_JWT_SCOPE    "caledonia"

#define GLEWLWYD_PLUGIN_OIDC_TABLE_CODE                 "gpo_code"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SCOPE           "gpo_code_scope"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SHEME           "gpo_code_scheme"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN        "gpo_refresh_token"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN_SCOPE  "gpo_refresh_token_scope"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN         "gpo_access_token"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN_SCOPE   "gpo_access_token_scope"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_ID_TOKEN             "gpo_id_token"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_SUBJECT_IDENTIFIER   "gpo_subject_identifier"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_CLIENT_REGISTRATION  "gpo_client_registration"
#define GLEWLWYD_PLUGIN_OIDC_TABLE_CLIENT_TOKEN_REQUEST "gpo_client_token_request"

// Authorization types available
#define GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE                  0
#define GLEWLWYD_AUTHORIZATION_TYPE_TOKEN                               1
#define GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN                            2
#define GLEWLWYD_AUTHORIZATION_TYPE_NONE                                3
#define GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS 4
#define GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS                  5
#define GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN                       6
#define GLEWLWYD_AUTHORIZATION_TYPE_DELETE_TOKEN                        7

#define GLEWLWYD_AUTHORIZATION_TYPE_NULL_FLAG                                0
#define GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE_FLAG                  1
#define GLEWLWYD_AUTHORIZATION_TYPE_TOKEN_FLAG                               2
#define GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN_FLAG                            4
#define GLEWLWYD_AUTHORIZATION_TYPE_NONE_FLAG                                8
#define GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS_FLAG 16
#define GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS_FLAG                  32
#define GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN_FLAG                       64
#define GLEWLWYD_AUTHORIZATION_TYPE_DELETE_TOKEN_FLAG                        128

#define GLEWLWYD_OIDC_SUBJECT_TYPE_PUBLIC   1
#define GLEWLWYD_OIDC_SUBJECT_TYPE_PAIRWISE 3
#define GLEWLWYD_SUB_LENGTH           32
#define GLEWLWYD_CLIENT_ID_LENGTH     16
#define GLEWLWYD_CLIENT_SECRET_LENGTH 32

#define GLEWLWYD_TOKEN_TYPE_CODE          0
#define GLEWLWYD_TOKEN_TYPE_ACCESS_TOKEN  1
#define GLEWLWYD_TOKEN_TYPE_USERINFO      2
#define GLEWLWYD_TOKEN_TYPE_ID_TOKEN      3
#define GLEWLWYD_TOKEN_TYPE_REFRESH_TOKEN 4

#define GLEWLWYD_AUTH_TOKEN_DEFAULT_MAX_AGE 3600
#define GLEWLWYD_AUTH_TOKEN_ASSERTION_TYPE "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

/**
 * Structure used to store all the plugin parameters and data duringexecution
 */
struct _oidc_config {
  struct config_plugin         * glewlwyd_config;
  const char                   * name;
  json_t                       * j_params;
  
  int                            jwt_key_size;
  jwt_t                        * jwt_sign;
  jwk_t                        * jwk_sign_default;
  int                            x5u_flags;
  
  char                         * discovery_str;
  char                         * jwks_str;
  char                         * check_session_iframe;
  
  json_int_t                     access_token_duration;
  json_int_t                     refresh_token_duration;
  json_int_t                     code_duration;
  json_int_t                     auth_token_max_age;
  unsigned short int             allow_non_oidc;
  unsigned short int             refresh_token_rolling;
  unsigned short int             auth_type_enabled[7];
  unsigned short int             subject_type;
  pthread_mutex_t                insert_lock;
  struct _oidc_resource_config * oidc_resource_config;
  struct _oidc_resource_config * introspect_revoke_resource_config;
  struct _oidc_resource_config * client_register_resource_config;
};

static size_t get_enc_key_size(jwa_enc enc) {
  size_t size = 0;
  switch (enc) {
    case R_JWA_ENC_A128CBC:
    case R_JWA_ENC_A128GCM:
    case R_JWA_ENC_A192GCM:
    case R_JWA_ENC_A256GCM:
      size = 32;
      break;
    case R_JWA_ENC_A192CBC:
      size = 48;
      break;
    case R_JWA_ENC_A256CBC:
      size = 64;
      break;
    default:
      size = 0;
      break;
  }
  return size;
}

static int get_key_size_from_alg(const char * str_alg) {
  if (0 == o_strcmp("HS256", str_alg)) {
    return 256;
  } else if (0 == o_strcmp("HS384", str_alg)) {
    return 384;
  } else if (0 == o_strcmp("HS512", str_alg)) {
    return 512;
  } else if (0 == o_strcmp("RS256", str_alg)) {
    return 256;
  } else if (0 == o_strcmp("RS384", str_alg)) {
    return 384;
  } else if (0 == o_strcmp("RS512", str_alg)) {
    return 512;
  } else if (0 == o_strcmp("ES256", str_alg)) {
    return 256;
  } else if (0 == o_strcmp("ES384", str_alg)) {
    return 384;
  } else if (0 == o_strcmp("ES512", str_alg)) {
    return 512;
  } else if (0 == o_strcmp("PS256", str_alg)) {
    return 256;
  } else if (0 == o_strcmp("PS384", str_alg)) {
    return 384;
  } else if (0 == o_strcmp("PS512", str_alg)) {
    return 512;
  } else if (0 == o_strcmp("EdDSA", str_alg)) {
    return 256;
  } else {
    return 0;
  }
}

/**
 * verify input parameters for the plugin instance
 */
static json_t * check_parameters (json_t * j_params) {
  json_t * j_element = NULL, * j_return = NULL, * j_error = json_array(), * j_scope;
  size_t index = 0, indexScope = 0;
  int ret = G_OK, has_openid = 0;
  jwks_t * jwks = NULL;
  
  if (j_error != NULL) {
    if (j_params == NULL) {
      json_array_append_new(j_error, json_string("parameters invalid"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "iss") == NULL || !json_string_length(json_object_get(j_params, "iss"))) {
      json_array_append_new(j_error, json_string("iss is mandatory must be a non empty string"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "jwks-uri") != NULL && !json_is_string(json_object_get(j_params, "jwks-uri"))) {
      json_array_append_new(j_error, json_string("jwks-uri is optional must be a string"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "jwks-private") != NULL && !json_is_string(json_object_get(j_params, "jwks-private"))) {
      json_array_append_new(j_error, json_string("jwks-private is optional must be a string"));
      ret = G_ERROR_PARAM;
    }
    if (json_string_length(json_object_get(j_params, "jwks-uri")) || json_string_length(json_object_get(j_params, "jwks-private"))) {
      if (json_object_get(j_params, "default-kid") != NULL && !json_is_string(json_object_get(j_params, "default-kid"))) {
        json_array_append_new(j_error, json_string("default-kid is optional must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-sign_kid-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-sign_kid-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-sign_kid-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_string_length(json_object_get(j_params, "jwks-uri"))) {
        if (r_jwks_init(&jwks) != RHN_OK || r_jwks_import_from_uri(jwks, json_string_value(json_object_get(j_params, "jwks-uri")), R_FLAG_FOLLOW_REDIRECT|(json_object_get(j_params, "request-uri-allow-https-non-secure")==json_true()?R_FLAG_IGNORE_SERVER_CERTIFICATE:0)) != RHN_OK) {
          json_array_append_new(j_error, json_string("jwks-uri leads to an invalid jwks"));
          ret = G_ERROR_PARAM;
        }
        r_jwks_free(jwks);
      } else {
        if (r_jwks_init(&jwks) != RHN_OK || r_jwks_import_from_str(jwks, json_string_value(json_object_get(j_params, "jwks-private"))) != RHN_OK) {
          json_array_append_new(j_error, json_string("jwks-private is an invalid jwks"));
          ret = G_ERROR_PARAM;
        }
        r_jwks_free(jwks);
      }
    } else {
      if (0 != o_strcmp("rsa", json_string_value(json_object_get(j_params, "jwt-type"))) &&
          0 != o_strcmp("ecdsa", json_string_value(json_object_get(j_params, "jwt-type"))) &&
          0 != o_strcmp("eddsa", json_string_value(json_object_get(j_params, "jwt-type"))) &&
          0 != o_strcmp("rsa-pss", json_string_value(json_object_get(j_params, "jwt-type"))) &&
          0 != o_strcmp("sha", json_string_value(json_object_get(j_params, "jwt-type")))) {
        json_array_append_new(j_error, json_string("jwt-type must be a string and have one of the following values: 'rsa', 'ecdsa', 'eddsa', 'rsa-pss', 'sha'"));
        ret = G_ERROR_PARAM;
      }
      if (0 != o_strcmp("256", json_string_value(json_object_get(j_params, "jwt-key-size"))) &&
          0 != o_strcmp("384", json_string_value(json_object_get(j_params, "jwt-key-size"))) &&
          0 != o_strcmp("512", json_string_value(json_object_get(j_params, "jwt-key-size")))) {
        json_array_append_new(j_error, json_string("jwt-key-size must be a string and have one of the following values: '256', '384', '512'"));
        ret = G_ERROR_PARAM;
      }
      if ((0 == o_strcmp("rsa", json_string_value(json_object_get(j_params, "jwt-type"))) ||
           0 == o_strcmp("ecdsa", json_string_value(json_object_get(j_params, "jwt-type"))) ||
           0 == o_strcmp("eddsa", json_string_value(json_object_get(j_params, "jwt-type"))) ||
           0 == o_strcmp("rsa-pss", json_string_value(json_object_get(j_params, "jwt-type")))) && 
           (json_object_get(j_params, "key") == NULL || json_object_get(j_params, "cert") == NULL ||
           !json_is_string(json_object_get(j_params, "key")) || !json_is_string(json_object_get(j_params, "cert")) || !json_string_length(json_object_get(j_params, "key")) || !json_string_length(json_object_get(j_params, "cert")))) {
        json_array_append_new(j_error, json_string("Properties 'cert' and 'key' are mandatory and must be strings"));
        ret = G_ERROR_PARAM;
      } else if (0 == o_strcmp("sha", json_string_value(json_object_get(j_params, "jwt-type"))) &&
         (json_object_get(j_params, "key") == NULL || !json_is_string(json_object_get(j_params, "key")) || !json_string_length(json_object_get(j_params, "key")))) {
        json_array_append_new(j_error, json_string("Property 'key' is mandatory and must be a string"));
        ret = G_ERROR_PARAM;
      }
    }

    if (json_object_get(j_params, "access-token-duration") != NULL && (!json_is_integer(json_object_get(j_params, "access-token-duration")) || json_integer_value(json_object_get(j_params, "access-token-duration")) <= 0)) {
      json_array_append_new(j_error, json_string("Property 'access-token-duration' is optional and must be a non null positive integer"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "refresh-token-duration") != NULL && (!json_is_integer(json_object_get(j_params, "refresh-token-duration")) || json_integer_value(json_object_get(j_params, "refresh-token-duration")) <= 0)) {
      json_array_append_new(j_error, json_string("Property 'access-token-duration' is optional and must be a non null positive integer"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "refresh-token-rolling") != NULL && !json_is_boolean(json_object_get(j_params, "refresh-token-rolling"))) {
      json_array_append_new(j_error, json_string("Property 'refresh-token-rolling' is optional and must be a non null positive integer"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-code-enabled") != NULL && !json_is_boolean(json_object_get(j_params, "auth-type-code-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-code-enabled' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-token-enabled") != NULL && !json_is_boolean(json_object_get(j_params, "auth-type-token-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-token-enabled' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-none-enabled") != NULL && !json_is_boolean(json_object_get(j_params, "auth-type-none-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-none-enabled' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-password-enabled") != NULL && !json_is_boolean(json_object_get(j_params, "auth-type-password-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-password-enabled' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-client-enabled") != NULL && !json_is_boolean(json_object_get(j_params, "auth-type-client-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-client-enabled' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "auth-type-refresh-enabled") != NULL && !json_is_boolean(json_object_get(j_params, "auth-type-refresh-enabled"))) {
      json_array_append_new(j_error, json_string("Property 'auth-type-refresh-enabled' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "allow-non-oidc") != NULL && !json_is_boolean(json_object_get(j_params, "allow-non-oidc"))) {
      json_array_append_new(j_error, json_string("Property 'allow-non-oidc' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "issuer") != NULL && !json_is_string(json_object_get(j_params, "issuer"))) {
      json_array_append_new(j_error, json_string("Property 'issuer' is optional and must be a string"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "service-documentation") != NULL && !json_is_string(json_object_get(j_params, "service-documentation"))) {
      json_array_append_new(j_error, json_string("Property 'service-documentation' is optional and must be a string"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "op-policy-uri") != NULL && !json_is_string(json_object_get(j_params, "op-policy-uri"))) {
      json_array_append_new(j_error, json_string("Property 'op-policy-uri' is optional and must be a string"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "op-tos-uri") != NULL && !json_is_string(json_object_get(j_params, "op-tos-uri"))) {
      json_array_append_new(j_error, json_string("Property 'op-tos-uri' is optional and must be a string"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "jwks-show") != NULL && !json_is_boolean(json_object_get(j_params, "jwks-show"))) {
      json_array_append_new(j_error, json_string("Property 'jwks-show' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "jwks-x5c") != NULL && !json_is_array(json_object_get(j_params, "jwks-x5c"))) {
      json_array_append_new(j_error, json_string("Property 'jwks-x5c' is optional and must be an array of strings"));
      ret = G_ERROR_PARAM;
    } else {
      json_array_foreach(json_object_get(j_params, "jwks-x5c"), index, j_element) {
        if (!json_string_length(j_element)) {
          json_array_append_new(j_error, json_string("Property 'jwks-x5c' is optional and must be an array of strings"));
          ret = G_ERROR_PARAM;
        }
      }
    }
    if (json_object_get(j_params, "request-parameter-allow") != NULL && !json_is_boolean(json_object_get(j_params, "request-parameter-allow"))) {
      json_array_append_new(j_error, json_string("Property 'request-parameter-allow' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "request-parameter-allow") == json_true()) {
      if (json_object_get(j_params, "request-uri-allow-https-non-secure") != NULL && !json_is_boolean(json_object_get(j_params, "request-uri-allow-https-non-secure"))) {
        json_array_append_new(j_error, json_string("Property 'request-uri-allow-https-non-secure' is optional and must be a boolean"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "request-parameter-allow-encrypted") != NULL && !json_is_boolean(json_object_get(j_params, "request-parameter-allow-encrypted"))) {
        json_array_append_new(j_error, json_string("Property 'request-parameter-allow-encrypted' is optional and must be a boolean"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "request-maximum-exp") != NULL && json_integer_value(json_object_get(j_params, "request-maximum-exp")) <= 0) {
        json_array_append_new(j_error, json_string("Property 'request-maximum-exp' is optional and must be a positive integer"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-pubkey-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-pubkey-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-pubkey-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-jwks-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-jwks-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-jwks-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-jwks_uri-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-jwks_uri-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-jwks_uri-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "encrypt-out-token-allow") != NULL && !json_is_boolean(json_object_get(j_params, "encrypt-out-token-allow"))) {
        json_array_append_new(j_error, json_string("Property 'encrypt-out-token-allow' is optional and must be a boolean"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-alg-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-alg-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-alg-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-enc-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-enc-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-enc-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-alg_kid-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-alg_kid-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-alg_kid-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-encrypt_code-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-encrypt_code-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-encrypt_code-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-encrypt_at-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-encrypt_at-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-encrypt_at-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-encrypt_userinfo-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-encrypt_userinfo-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-encrypt_userinfo-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-encrypt_id_token-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-encrypt_id_token-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-encrypt_id_token-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
      if (json_object_get(j_params, "client-encrypt_refresh_token-parameter") != NULL && !json_is_string(json_object_get(j_params, "client-encrypt_refresh_token-parameter"))) {
        json_array_append_new(j_error, json_string("Property 'client-encrypt_refresh_token-parameter' is optional and must be a string"));
        ret = G_ERROR_PARAM;
      }
    }
    if (json_object_get(j_params, "subject-type") != NULL && 0 != o_strcmp("public", json_string_value(json_object_get(j_params, "subject-type"))) && 0 != o_strcmp("pairwise", json_string_value(json_object_get(j_params, "subject-type")))) {
      json_array_append_new(j_error, json_string("Property 'op-tos-uri' is optional and must have one of the following values: 'public' or 'pairwise'"));
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
            if (json_object_get(j_element, "name") == NULL || !json_is_string(json_object_get(j_element, "name")) || !json_string_length(json_object_get(j_element, "name"))) {
              json_array_append_new(j_error, json_string("'scope' element must have a property 'name' of type string and non empty"));
              ret = G_ERROR_PARAM;
            } else if (json_object_get(j_element, "refresh-token-rolling") != NULL && !json_is_boolean(json_object_get(j_element, "refresh-token-rolling"))) {
              json_array_append_new(j_error, json_string("'scope' element can have a property 'refresh-token-rolling' of type boolean"));
              ret = G_ERROR_PARAM;
            } else if (json_object_get(j_element, "refresh-token-duration") != NULL && (!json_is_integer(json_object_get(j_element, "refresh-token-duration")) || json_integer_value(json_object_get(j_element, "refresh-token-duration")) <= 0)) {
              json_array_append_new(j_error, json_string("'scope' element can have a property 'refresh-token-duration' of type integer and non null positive value"));
              ret = G_ERROR_PARAM;
            }
          }
        }
      }
    }
    if (json_object_get(j_params, "additional-parameters") != NULL) {
      if (!json_is_array(json_object_get(j_params, "additional-parameters"))) {
        json_array_append_new(j_error, json_string("Property 'additional-parameters' is optional and must be an array"));
        ret = G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_params, "additional-parameters"), index, j_element) {
          if (!json_is_object(j_element)) {
            json_array_append_new(j_error, json_string("'additional-parameters' element must be a JSON object"));
            ret = G_ERROR_PARAM;
          } else {
            if (json_object_get(j_element, "user-parameter") == NULL || !json_is_string(json_object_get(j_element, "user-parameter")) || !json_string_length(json_object_get(j_element, "user-parameter"))) {
              json_array_append_new(j_error, json_string("'additional-parameters' element must have a property 'user-parameter' of type string and non empty"));
              ret = G_ERROR_PARAM;
            } else if (json_object_get(j_element, "token-parameter") == NULL || !json_is_string(json_object_get(j_element, "token-parameter")) || !json_string_length(json_object_get(j_element, "token-parameter"))) {
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
    if (json_object_get(j_params, "claims") != NULL) {
      if (!json_is_array(json_object_get(j_params, "claims"))) {
        json_array_append_new(j_error, json_string("Property 'claims' is optional and must be an array"));
        ret = G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_params, "claims"), index, j_element) {
          if (!json_is_object(j_element)) {
            json_array_append_new(j_error, json_string("'claims' element must be a JSON object"));
            ret = G_ERROR_PARAM;
          } else {
            if (json_object_get(j_element, "name") == NULL || !json_string_length(json_object_get(j_element, "name"))) {
              json_array_append_new(j_error, json_string("'claims' element must have a property 'name' of type string and non empty"));
              ret = G_ERROR_PARAM;
            } else if (0 == o_strcmp("iss", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("sub", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("aud", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("exp", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("iat", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("auth_time", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("nonce", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("acr", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("amr", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("azp", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("name", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("email", json_string_value(json_object_get(j_element, "name"))) ||
                       0 == o_strcmp("address", json_string_value(json_object_get(j_element, "name")))) {
              json_array_append_new(j_error, json_string("'claims' property 'name' forbidden values are: 'iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'azp', 'name', 'email', 'address'"));
              ret = G_ERROR_PARAM;
            }
            if (json_object_get(j_element, "user-property") == NULL || !json_string_length(json_object_get(j_element, "user-property"))) {
              json_array_append_new(j_error, json_string("'claims' element must have a property 'user-property' of type string and non empty"));
              ret = G_ERROR_PARAM;
            }
            if (json_object_get(j_element, "type") != NULL && 0 != o_strcmp("string", json_string_value(json_object_get(j_element, "type"))) && 0 != o_strcmp("boolean", json_string_value(json_object_get(j_element, "type"))) && 0 != o_strcmp("number", json_string_value(json_object_get(j_element, "type")))) {
              json_array_append_new(j_error, json_string("'claims' element 'type' is optional and must be of type string and must have one of the following values: 'string', 'boolean', 'number'"));
              ret = G_ERROR_PARAM;
            } else if (0 == o_strcmp("boolean", json_string_value(json_object_get(j_element, "type")))) {
              if (json_object_get(j_element, "boolean-value-true") == NULL || !json_string_length(json_object_get(j_element, "boolean-value-true")) ||
                  json_object_get(j_element, "boolean-value-false") == NULL || !json_string_length(json_object_get(j_element, "boolean-value-false"))) {
                json_array_append_new(j_error, json_string("'claims' elements 'boolean-value-true' and 'boolean-value-true' are mandatory when type is 'boolean' and they must be non empty strings"));
                ret = G_ERROR_PARAM;
              }
            }
            if (json_object_get(j_element, "mandatory") != NULL && !json_is_boolean(json_object_get(j_element, "mandatory"))) {
              json_array_append_new(j_error, json_string("'claims' element 'mandatory' is optional and must be a boolean"));
              ret = G_ERROR_PARAM;
            }
            if (json_object_get(j_element, "on-demand") != NULL && !json_is_boolean(json_object_get(j_element, "on-demand"))) {
              json_array_append_new(j_error, json_string("'claims' element 'on-demand' is optional and must be a boolean"));
              ret = G_ERROR_PARAM;
            }
            if (json_object_get(j_element, "scope") != NULL && !json_is_array(json_object_get(j_element, "scope"))) {
              json_array_append_new(j_error, json_string("'claims' element 'scope' is optional and must be a JSON array of strings"));
              ret = G_ERROR_PARAM;
            } else if (json_object_get(j_element, "scope")) {
              json_array_foreach(json_object_get(j_element, "scope"), indexScope, j_scope) {
                if (!json_string_length(j_scope)) {
                  json_array_append_new(j_error, json_string("'claims' element 'scope' is optional and must be a JSON array of strings"));
                  ret = G_ERROR_PARAM;
                }
              }
            }
          }
        }
      }
    }
    if (json_object_get(j_params, "name-claim") != NULL && 0 != o_strcmp("no", json_string_value(json_object_get(j_params, "name-claim"))) && 0 != o_strcmp("on-demand", json_string_value(json_object_get(j_params, "name-claim"))) && 0 != o_strcmp("mandatory", json_string_value(json_object_get(j_params, "name-claim")))) {
      json_array_append_new(j_error, json_string("Property 'name-claim' is optional and must have one of the following values: 'no', 'on-demand' or 'mandatory'"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "name-claim-scope") != NULL && !json_is_array(json_object_get(j_params, "name-claim-scope"))) {
      json_array_append_new(j_error, json_string("Property 'name-claim-scope' is optional and must be an array of strings"));
      ret = G_ERROR_PARAM;
    } else if (json_object_get(j_params, "name-claim-scope") != NULL) {
      json_array_foreach(json_object_get(j_params, "name-claim-scope"), indexScope, j_scope) {
        if (!json_string_length(j_scope)) {
          json_array_append_new(j_error, json_string("Property 'name-claim-scope' is optional and must be an array of strings"));
          ret = G_ERROR_PARAM;
        }
      }
    }
    if (json_object_get(j_params, "email-claim") != NULL && 0 != o_strcmp("no", json_string_value(json_object_get(j_params, "email-claim"))) && 0 != o_strcmp("on-demand", json_string_value(json_object_get(j_params, "email-claim"))) && 0 != o_strcmp("mandatory", json_string_value(json_object_get(j_params, "email-claim")))) {
      json_array_append_new(j_error, json_string("Property 'email-claim' is optional and must have one of the following values: 'no', 'on-demand' or 'mandatory'"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "email-claim-scope") != NULL && !json_is_array(json_object_get(j_params, "email-claim-scope"))) {
      json_array_append_new(j_error, json_string("Property 'email-claim-scope' is optional and must be an array of strings"));
      ret = G_ERROR_PARAM;
    } else if (json_object_get(j_params, "email-claim-scope") != NULL) {
      json_array_foreach(json_object_get(j_params, "email-claim-scope"), indexScope, j_scope) {
        if (!json_string_length(j_scope)) {
          json_array_append_new(j_error, json_string("Property 'email-claim-scope' is optional and must be an array of strings"));
          ret = G_ERROR_PARAM;
        }
      }
    }
    if (json_object_get(j_params, "address-claim") != NULL) {
      if (!json_is_object(json_object_get(j_params, "address-claim"))) {
        json_array_append_new(j_error, json_string("Property 'address-claim' is optional and must be a JSON object"));
        ret = G_ERROR_PARAM;
      } else if (0 != o_strcmp("no", json_string_value(json_object_get(json_object_get(j_params, "address-claim"), "type"))) && 0 != o_strcmp("on-demand", json_string_value(json_object_get(json_object_get(j_params, "address-claim"), "type"))) && 0 != o_strcmp("mandatory", json_string_value(json_object_get(json_object_get(j_params, "address-claim"), "type")))) {
        json_array_append_new(j_error, json_string("Property 'address-claim' type is mandatory and must have one of the following values: 'no', 'on-demand' or 'mandatory'"));
        ret = G_ERROR_PARAM;
      } else {
        if (json_object_get(json_object_get(j_params, "address-claim"), "formatted") != NULL && !json_is_string(json_object_get(json_object_get(j_params, "address-claim"), "formatted"))) {
          json_array_append_new(j_error, json_string("Property 'address-claim'.'formatted' is optional and must be a string"));
          ret = G_ERROR_PARAM;
        }
        if (json_object_get(json_object_get(j_params, "address-claim"), "street_address") != NULL && !json_is_string(json_object_get(json_object_get(j_params, "address-claim"), "street_address"))) {
          json_array_append_new(j_error, json_string("Property 'address-claim'.'street_address' is optional and must be a string"));
          ret = G_ERROR_PARAM;
        }
        if (json_object_get(json_object_get(j_params, "address-claim"), "locality") != NULL && !json_is_string(json_object_get(json_object_get(j_params, "address-claim"), "locality"))) {
          json_array_append_new(j_error, json_string("Property 'address-claim'.'locality' is optional and must be a string"));
          ret = G_ERROR_PARAM;
        }
        if (json_object_get(json_object_get(j_params, "address-claim"), "region") != NULL && !json_is_string(json_object_get(json_object_get(j_params, "address-claim"), "region"))) {
          json_array_append_new(j_error, json_string("Property 'address-claim'.'region' is optional and must be a string"));
          ret = G_ERROR_PARAM;
        }
        if (json_object_get(json_object_get(j_params, "address-claim"), "postal_code") != NULL && !json_is_string(json_object_get(json_object_get(j_params, "address-claim"), "postal_code"))) {
          json_array_append_new(j_error, json_string("Property 'address-claim'.'postal_code' is optional and must be a string"));
          ret = G_ERROR_PARAM;
        }
        if (json_object_get(json_object_get(j_params, "address-claim"), "country") != NULL && !json_is_string(json_object_get(json_object_get(j_params, "address-claim"), "country"))) {
          json_array_append_new(j_error, json_string("Property 'address-claim'.'country' is optional and must be a string"));
          ret = G_ERROR_PARAM;
        }
      }
    }
    if (json_object_get(j_params, "allowed-scope") != NULL) {
      if (!json_is_array(json_object_get(j_params, "allowed-scope"))) {
        json_array_append_new(j_error, json_string("Property 'allowed-scope' is optional and must be an array of strings that includes the value 'openid'"));
        ret = G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_params, "allowed-scope"), index, j_element) {
          if (!json_string_length(j_element)) {
            json_array_append_new(j_error, json_string("Property 'allowed-scope' is optional and must be an array of strings that includes the value 'openid'"));
            ret = G_ERROR_PARAM;
          } else if (0 == o_strcmp("openid", json_string_value(j_element))) {
            has_openid = 1;
          }
        }
        if (!has_openid) {
          json_array_append_new(j_error, json_string("Property 'allowed-scope' is optional and must be an array of strings that includes the value 'openid'"));
          ret = G_ERROR_PARAM;
        }
      }
    }
    if (json_object_get(j_params, "limit-clients-scopes") != NULL && !json_is_boolean(json_object_get(j_params, "limit-clients-scopes"))) {
      json_array_append_new(j_error, json_string("Property 'limit-clients-scopes' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
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
    if (json_object_get(j_params, "session-management-allowed") != NULL && !json_is_boolean(json_object_get(j_params, "session-management-allowed"))) {
      json_array_append_new(j_error, json_string("Property 'session-management-allowed' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "introspection-revocation-allowed") == json_true()) {
      if (json_object_get(j_params, "introspection-revocation-auth-scope") != NULL && !json_is_array(json_object_get(j_params, "introspection-revocation-auth-scope"))) {
        json_array_append_new(j_error, json_string("Property 'introspection-revocation-auth-scope' is optional and must be a JSON array of strings, maximum 128 characters"));
        ret = G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_params, "introspection-revocation-auth-scope"), index, j_element) {
          if (!json_string_length(j_element) || json_string_length(j_element) > 128) {
            json_array_append_new(j_error, json_string("Property 'introspection-revocation-auth-scope' is optional and must be a non empty JSON array of strings, maximum 128 characters"));
            ret = G_ERROR_PARAM;
          }
        }
      }
      if (json_object_get(j_params, "introspection-revocation-allow-target-client") != NULL && !json_is_boolean(json_object_get(j_params, "introspection-revocation-allow-target-client"))) {
        json_array_append_new(j_error, json_string("Property 'introspection-revocation-allow-target-client' is optional and must be a boolean"));
        ret = G_ERROR_PARAM;
      }
    }
    if (json_object_get(j_params, "register-client-allowed") != NULL && !json_is_boolean(json_object_get(j_params, "register-client-allowed"))) {
      json_array_append_new(j_error, json_string("Property 'client-register-allowed' is optional and must be a boolean"));
      ret = G_ERROR_PARAM;
    }
    if (json_object_get(j_params, "register-client-allowed") == json_true()) {
      if (json_object_get(j_params, "register-client-auth-scope") != NULL && !json_is_array(json_object_get(j_params, "register-client-auth-scope"))) {
        json_array_append_new(j_error, json_string("Property 'register-client-auth-scope' is optional and must be a JSON array of strings, maximum 128 characters"));
        ret = G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_params, "register-client-auth-scope"), index, j_element) {
          if (!json_string_length(j_element) || json_string_length(j_element) > 128) {
            json_array_append_new(j_error, json_string("Property 'register-client-auth-scope' is optional and must be a JSON array of strings, maximum 128 characters"));
            ret = G_ERROR_PARAM;
          }
        }
      }
      if (json_object_get(j_params, "register-client-credentials-scope") != NULL && !json_is_array(json_object_get(j_params, "register-client-credentials-scope"))) {
        json_array_append_new(j_error, json_string("Property 'register-client-credentials-scope' is optional and must be a JSON array of strings, maximum 128 characters"));
        ret = G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_params, "register-client-credentials-scope"), index, j_element) {
          if (!json_string_length(j_element) || json_string_length(j_element) > 128) {
            json_array_append_new(j_error, json_string("Property 'register-client-credentials-scope' is mandatory and must be a non empty JSON array of strings, maximum 128 characters"));
            ret = G_ERROR_PARAM;
          }
        }
      }
    }
    if (json_array_size(j_error) && ret == G_ERROR_PARAM) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{si}", "result", ret);
    }
    json_decref(j_error);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "check_parameters oidc - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

/**
 * Return the struct _u_map corresponding to the
 * request context (POST or GET) to retrieve parameters
 */
static struct _u_map * get_map(const struct _u_request * request) {
  if (0 == o_strcmp(request->http_verb, "POST")) {
    return request->map_post_body;
  } else {
    return request->map_url;
  }
}

/**
 * return true if the JSON array has a element matching value
 */
static int json_array_has_string(json_t * j_array, const char * value) {
  json_t * j_element = NULL;
  size_t index = 0;
  
  json_array_foreach(j_array, index, j_element) {
    if (json_is_string(j_element) && 0 == o_strcmp(value, json_string_value(j_element))) {
      return 1;
    }
  }
  return 0;
}

/**
 * Get sub associated with username in public mode
 * Or create one and store it in the database if it doesn't exist
 */
static char * get_sub_public(struct _oidc_config * config, const char * username) {
  json_t * j_query, * j_result;
  int res;
  char * sub = NULL;
  
  j_query = json_pack("{sss[s]s{sssssoso}}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_SUBJECT_IDENTIFIER,
                      "columns",
                        "gposi_sub",
                      "where",
                        "gposi_plugin_name",
                        config->name,
                        "gposi_username",
                        username,
                        "gposi_client_id",
                        json_null(),
                        "gposi_sector_identifier_uri",
                        json_null());
  res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      sub = o_strdup(json_string_value(json_object_get(json_array_get(j_result, 0), "gposi_sub")));
    } else {
      sub = o_malloc((GLEWLWYD_SUB_LENGTH+1)*sizeof(char));
      if (sub != NULL) {
        *sub = '\0';
        rand_string(sub, GLEWLWYD_SUB_LENGTH);
        j_query = json_pack("{sss{sssssssoso}}",
                            "table",
                            GLEWLWYD_PLUGIN_OIDC_TABLE_SUBJECT_IDENTIFIER,
                            "values",
                              "gposi_plugin_name",
                              config->name,
                              "gposi_sub",
                              sub,
                              "gposi_username",
                              username,
                              "gposi_client_id",
                              json_null(),
                              "gposi_sector_identifier_uri",
                              json_null());
        if (h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL) != H_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_sub_public - Error executing h_insert");
          o_free(sub);
          sub = NULL;
        }
        json_decref(j_query);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_sub_public - Error allocating resources for sub");
      }
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_sub_public - Error executing h_select");
  }
  return sub;
}

/**
 * Get sub associated with username and client in public mode
 * Or create one and store it in the database if it doesn't exist
 */
static char * get_sub_pairwise(struct _oidc_config * config, const char * username, json_t * j_client) {
  json_t * j_query, * j_result;
  int res;
  char * sub = NULL;
  
  j_query = json_pack("{sss[s]s{ssss}}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_SUBJECT_IDENTIFIER,
                      "columns",
                        "gposi_sub",
                      "where",
                        "gposi_plugin_name",
                        config->name,
                        "gposi_username",
                        username);

  if (json_string_length(json_object_get(j_client, "sector_identifier_uri"))) {
    json_object_set(json_object_get(j_query, "where"), "gposi_sector_identifier_uri", json_object_get(j_client, "sector_identifier_uri"));
    json_object_set(json_object_get(j_query, "where"), "gposi_client_id", json_null());
  } else {
    json_object_set(json_object_get(j_query, "where"), "gposi_sector_identifier_uri", json_null());
    json_object_set(json_object_get(j_query, "where"), "gposi_client_id", json_object_get(j_client, "client_id"));
  }
  res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      sub = o_strdup(json_string_value(json_object_get(json_array_get(j_result, 0), "gposi_sub")));
    } else {
      sub = o_malloc((GLEWLWYD_SUB_LENGTH+1)*sizeof(char));
      if (sub != NULL) {
        *sub = '\0';
        rand_string(sub, GLEWLWYD_SUB_LENGTH);
        j_query = json_pack("{sss{ssssss}}",
                            "table",
                            GLEWLWYD_PLUGIN_OIDC_TABLE_SUBJECT_IDENTIFIER,
                            "values",
                              "gposi_plugin_name",
                              config->name,
                              "gposi_sub",
                              sub,
                              "gposi_username",
                              username);
        if (json_string_length(json_object_get(j_client, "sector_identifier_uri"))) {
          json_object_set(json_object_get(j_query, "values"), "gposi_sector_identifier_uri", json_object_get(j_client, "sector_identifier_uri"));
          json_object_set(json_object_get(j_query, "where"), "gposi_client_id", json_null());
        } else {
          json_object_set(json_object_get(j_query, "values"), "gposi_sector_identifier_uri", json_null());
          json_object_set(json_object_get(j_query, "where"), "gposi_client_id", json_object_get(j_client, "client_id"));
        }
        if (h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL) != H_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_sub_pairwise - Error executing h_insert");
          o_free(sub);
          sub = NULL;
        }
        json_decref(j_query);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_sub_pairwise - Error allocating resources for sub");
      }
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_sub_pairwise - Error executing h_select");
  }
  return sub;
}

/**
 * Get sub associated with username and client
 * Or create one and store it in the database if it doesn't exist
 */
static char * get_sub(struct _oidc_config * config, const char * username, json_t * j_client) {
  if (config->subject_type == GLEWLWYD_OIDC_SUBJECT_TYPE_PUBLIC || j_client == NULL) {
    return get_sub_public(config, username);
  } else {
    return get_sub_pairwise(config, username, j_client);
  }
}

/**
 * Get username associated with a sub
 * Return NULL if not exist
 */
static char * get_username_from_sub(struct _oidc_config * config, const char * sub) {
  json_t * j_query, * j_result;
  int res;
  char * username = NULL;
  
  j_query = json_pack("{sss[s]s{ssss}}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_SUBJECT_IDENTIFIER,
                      "columns",
                        "gposi_username",
                      "where",
                        "gposi_plugin_name",
                        config->name,
                        "gposi_sub",
                        sub);
  res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      username = o_strdup(json_string_value(json_object_get(json_array_get(j_result, 0), "gposi_username")));
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_username_from_sub - Error executing h_select");
  }
  return username;
}

/**
 * Parse a single claim from a claim request
 */
static int is_claim_parameter_valid(json_t * j_claim) {
  json_t * j_element = NULL;
  size_t index = 0;
  
  if (json_is_null(j_claim)) {
    return G_OK;
  } else if (!json_is_object(j_claim)) {
    return G_ERROR_PARAM;
  } else {
    if (json_object_get(j_claim, "value") != NULL && !json_string_length(json_object_get(j_claim, "value"))) {
      return G_ERROR_PARAM;
    } else if (json_object_get(j_claim, "values")) {
      if (!json_is_array(json_object_get(j_claim, "values"))) {
        return G_ERROR_PARAM;
      } else {
        json_array_foreach(json_object_get(j_claim, "values"), index, j_element) {
          if (!json_string_length(j_element)) {
            return G_ERROR_PARAM;
          }
        }
      }
    }
    return G_OK;
  }
}

/**
 * parse claims parameter to validate that it has the correct format
 */
static int parse_claims_request(json_t * j_claims) {
  int ret = G_OK;
  json_t * j_claim_object, * j_element = NULL;
  const char * claim = NULL;
  
  if (json_is_object(j_claims)) {
    if ((j_claim_object = json_object_get(j_claims, "userinfo")) != NULL) {
      json_object_foreach(j_claim_object, claim, j_element) {
        if (is_claim_parameter_valid(j_element) != G_OK) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "parse_claims_request - Error claim %s in userinfo is not a valid claim parameter", claim);
          ret = G_ERROR_PARAM;
        }
      }
    }
    if ((j_claim_object = json_object_get(j_claims, "id_token")) != NULL) {
      json_object_foreach(j_claim_object, claim, j_element) {
        if (is_claim_parameter_valid(j_element) != G_OK) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "parse_claims_request - Error claim %s in id_token is not a valid claim parameter", claim);
          ret = G_ERROR_PARAM;
        }
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "parse_claims_request - Error j_claims not a JSON object");
    ret = G_ERROR_PARAM;
  }
  return ret;
}

/**
 * return the separator required to build a query string
 */
static char get_url_separator(const char * redirect_uri, int implicit_flow) {
  char sep = implicit_flow?'#':'?';
  
  if (o_strchr(redirect_uri, sep) != NULL) {
    sep = '&';
  }
  
  return sep;
}

static int is_encrypt_token_allowed(struct _oidc_config * config, json_t * j_client, int type) {
  const char * property, * value;
  switch (type) {
    case GLEWLWYD_TOKEN_TYPE_CODE:
      property = json_string_value(json_object_get(config->j_params, "client-encrypt_code-parameter"));
      break;
    case GLEWLWYD_TOKEN_TYPE_ACCESS_TOKEN:
      property = json_string_value(json_object_get(config->j_params, "client-encrypt_at-parameter"));
      break;
    case GLEWLWYD_TOKEN_TYPE_USERINFO:
      property = json_string_value(json_object_get(config->j_params, "client-encrypt_userinfo-parameter"));
      break;
    case GLEWLWYD_TOKEN_TYPE_ID_TOKEN:
      property = json_string_value(json_object_get(config->j_params, "client-encrypt_id_token-parameter"));
      break;
    case GLEWLWYD_TOKEN_TYPE_REFRESH_TOKEN:
      property = json_string_value(json_object_get(config->j_params, "client-encrypt_refresh_token-parameter"));
      break;
    default:
      property = NULL;
      break;
  }
  value = json_string_value(json_object_get(j_client, property));
  return (0 == o_strcmp("1", value) || 0 == o_strcasecmp("yes", value) || 0 == o_strcasecmp("true", value) || 0 == o_strcasecmp("indeed, my friend", value));
}

static char * encrypt_token_if_required(struct _oidc_config * config, const char * token, json_t * j_client, int type) {
  char * token_out = NULL;
  unsigned char key[64] = {0};
  size_t key_len = 64;
  jwk_t * jwk = NULL;
  jwks_t * jwks;
  jwe_t * jwe = NULL;
  jwa_alg alg;
  jwa_enc enc;
  const char * jwks_uri_p = json_string_value(json_object_get(config->j_params, "client-jwks_uri-parameter")), 
             * jwks_p = json_string_value(json_object_get(config->j_params, "client-jwks-parameter")), 
             * pubkey_p = json_string_value(json_object_get(config->j_params, "client-pubkey-parameter")), 
             * enc_p = json_string_value(json_object_get(config->j_params, "client-enc-parameter")), 
             * alg_p = json_string_value(json_object_get(config->j_params, "client-alg-parameter")), 
             * alg_kid_p = json_string_value(json_object_get(config->j_params, "client-alg_kid-parameter"));
  
  if (j_client != NULL && json_object_get(j_client, "confidential") == json_true() && json_object_get(j_client, alg_p) != NULL && is_encrypt_token_allowed(config, j_client, type) && json_object_get(config->j_params, "encrypt-out-token-allow") == json_true()) {
    if (r_jwe_init(&jwe) == RHN_OK && 
        r_jwe_set_payload(jwe, (const unsigned char *)token, o_strlen(token)) == RHN_OK && 
        ((json_object_get(j_client, enc_p) != NULL && r_jwe_set_enc(jwe, r_str_to_jwa_enc(json_string_value(json_object_get(j_client, enc_p)))) == RHN_OK) || 
         (json_object_get(j_client, enc_p) == NULL && r_jwe_set_enc(jwe, R_JWA_ENC_A128CBC) == RHN_OK)) && 
        r_jwe_set_alg(jwe, r_str_to_jwa_alg(json_string_value(json_object_get(j_client, alg_p)))) == RHN_OK) {
      if (type != GLEWLWYD_TOKEN_TYPE_REFRESH_TOKEN && type != GLEWLWYD_TOKEN_TYPE_CODE) {
        r_jwe_set_header_str_value(jwe, "cty", "JWT");
        r_jwe_set_header_str_value(jwe, "typ", "JWT");
      }
      alg = r_jwe_get_alg(jwe);
      enc = r_jwe_get_enc(jwe);
      if (alg == R_JWA_ALG_A128GCMKW || alg == R_JWA_ALG_A128KW || alg == R_JWA_ALG_A192GCMKW || alg == R_JWA_ALG_A192KW || alg == R_JWA_ALG_A256GCMKW || alg == R_JWA_ALG_A256KW || alg == R_JWA_ALG_DIR) {
        if (json_string_length(json_object_get(j_client, "client_secret"))) {
          if (generate_digest_raw((alg == R_JWA_ALG_DIR?digest_SHA512:digest_SHA256), (const unsigned char *)json_string_value(json_object_get(j_client, "client_secret")), json_string_length(json_object_get(j_client, "client_secret")), key, &key_len)) {
            if (alg == R_JWA_ALG_DIR) {
              key_len = get_enc_key_size(enc);
            } else if (alg == R_JWA_ALG_A128GCMKW || alg == R_JWA_ALG_A128KW) {
              key_len = 16;
            } else if (alg == R_JWA_ALG_A192GCMKW || alg == R_JWA_ALG_A192KW) {
              key_len = 24;
            }
            if (r_jwk_init(&jwk) != RHN_OK || r_jwk_import_from_symmetric_key(jwk, key, key_len) != RHN_OK) {
              y_log_message(Y_LOG_LEVEL_ERROR, "encrypt_token_if_required - Error setting jwk, client_id %s", json_string_value(json_object_get(j_client, "client_id")));
              r_jwk_free(jwk);
              jwk = NULL;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "encrypt_token_if_required - Error generate_digest_raw, client_id %s", json_string_value(json_object_get(j_client, "client_id")));
          }
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "encrypt_token_if_required - client_id %s has no client_secret", json_string_value(json_object_get(j_client, "client_id")));
        }
      } else if (alg == R_JWA_ALG_ECDH_ES || alg == R_JWA_ALG_ECDH_ES_A128KW || alg == R_JWA_ALG_ECDH_ES_A192KW || alg == R_JWA_ALG_ECDH_ES_A256KW || alg == R_JWA_ALG_RSA1_5 || alg == R_JWA_ALG_RSA_OAEP || alg == R_JWA_ALG_RSA_OAEP_256) {
        if (r_jwks_init(&jwks) == RHN_OK) {
          if (json_string_length(json_object_get(j_client, jwks_uri_p)) && json_string_length(json_object_get(j_client, alg_kid_p))) {
            if (r_jwks_import_from_uri(jwks, json_string_value(json_object_get(j_client, jwks_uri_p)), config->x5u_flags) == RHN_OK) {
              if ((jwk = r_jwks_get_by_kid(jwks, json_string_value(json_object_get(j_client, alg_kid_p)))) == NULL) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "encrypt_token_if_required - unable to get pubkey from jwks_uri, client_id %s", json_string_value(json_object_get(j_client, "client_id")));
              }
            }
          } else if (json_is_object(json_object_get(j_client, jwks_p)) && json_string_length(json_object_get(j_client, alg_kid_p))) {
            if (r_jwks_import_from_json_t(jwks, json_object_get(j_client, jwks_p)) == RHN_OK) {
              if ((jwk = r_jwks_get_by_kid(jwks, json_string_value(json_object_get(j_client, alg_kid_p)))) == NULL) {
                y_log_message(Y_LOG_LEVEL_DEBUG, "encrypt_token_if_required - unable to get pubkey from jwks, client_id %s", json_string_value(json_object_get(j_client, "client_id")));
              }
            }
          } else if (json_string_length(json_object_get(j_client, pubkey_p))) {
            if (r_jwk_init(&jwk) != RHN_OK || r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (const unsigned char *)json_string_value(json_object_get(j_client, pubkey_p)), json_string_length(json_object_get(j_client, pubkey_p))) != RHN_OK) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "encrypt_token_if_required - unable to get pubkey from client, client_id %s", json_string_value(json_object_get(j_client, "client_id")));
              r_jwk_free(jwk);
              jwk = NULL;
            }
          }
          r_jwks_free(jwks);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "encrypt_token_if_required - Error r_jwks_init, client_id %s", json_string_value(json_object_get(j_client, "client_id")));
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "encrypt_token_if_required - Invalid key management algorithm for client_id %s", json_string_value(json_object_get(j_client, "client_id")));
      }
      if (jwk != NULL || alg == R_JWA_ALG_DIR) {
        token_out = r_jwe_serialize(jwe, jwk, 0);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "encrypt_token_if_required - Error setting values enc or alg for client_id %s", json_string_value(json_object_get(j_client, "client_id")));
    }
    r_jwe_free(jwe);
  } else {
    token_out = o_strdup(token);
  }
  r_jwk_free(jwk);
  return token_out;
}

/**
 * Generates a client_access_token from the specified parameters that are considered valid
 */
static char * generate_client_access_token(struct _oidc_config * config, json_t * j_client, const char * scope_list, time_t now, char * jti) {
  jwt_t * jwt;
  jwk_t * jwk;
  char * token = NULL;
  const char * sign_kid = json_string_value(json_object_get(config->j_params, "client-sign_kid-parameter"));
  
  jwt = r_jwt_copy(config->jwt_sign);
  if (jwt != NULL) {
    rand_string_nonce(jti, OIDC_JTI_LENGTH);
    if (j_client != NULL) {
      if (json_string_length(json_object_get(j_client, sign_kid))) {
        jwk = r_jwks_get_by_kid(config->jwt_sign->jwks_privkey_sign, json_string_value(json_object_get(j_client, sign_kid)));
      } else {
        jwk = r_jwk_copy(config->jwk_sign_default);
      }
    } else {
      jwk = r_jwk_copy(config->jwk_sign_default);
    }
    r_jwt_set_header_str_value(jwt, "typ", "at+jwt");
    // Build jwt payload
    r_jwt_set_claim_str_value(jwt, "iss", json_string_value(json_object_get(config->j_params, "iss")));
    r_jwt_set_claim_str_value(jwt, "aud", json_string_value(json_object_get(j_client, "client_id")));
    r_jwt_set_claim_str_value(jwt, "client_id", json_string_value(json_object_get(j_client, "client_id")));
    r_jwt_set_claim_int_value(jwt, "iat", now);
    r_jwt_set_claim_int_value(jwt, "exp", (now + config->access_token_duration));
    r_jwt_set_claim_int_value(jwt, "nbf", now);
    r_jwt_set_claim_str_value(jwt, "jti", jti);
    r_jwt_set_claim_str_value(jwt, "type", "client_token");
    r_jwt_set_claim_str_value(jwt, "scope", scope_list);
    token = r_jwt_serialize_signed(jwt, jwk, 0);
    r_jwk_free(jwk);
    if (token == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_client_access_token - Error generating token");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_client_access_token - Error cloning jwt");
  }
  r_jwt_free(jwt);
  return token;
}

/**
 * Extract address claim values from user properties
 */
static json_t * get_address_claim(struct _oidc_config * config, json_t * j_user) {
  json_t * j_return, * j_address, * j_value;
  
  if ((j_address = json_object()) != NULL) {
    if (json_string_length(json_object_get(json_object_get(config->j_params, "address-claim"), "formatted")) && (j_value = json_object_get(j_user, json_string_value(json_object_get(json_object_get(config->j_params, "address-claim"), "formatted")))) != NULL) {
      json_object_set(j_address, "formatted", j_value);
    }
    if (json_string_length(json_object_get(json_object_get(config->j_params, "address-claim"), "street_address")) && (j_value = json_object_get(j_user, json_string_value(json_object_get(json_object_get(config->j_params, "address-claim"), "street_address")))) != NULL) {
      json_object_set(j_address, "street_address", j_value);
    }
    if (json_string_length(json_object_get(json_object_get(config->j_params, "address-claim"), "locality")) && (j_value = json_object_get(j_user, json_string_value(json_object_get(json_object_get(config->j_params, "address-claim"), "locality")))) != NULL) {
      json_object_set(j_address, "locality", j_value);
    }
    if (json_string_length(json_object_get(json_object_get(config->j_params, "address-claim"), "region")) && (j_value = json_object_get(j_user, json_string_value(json_object_get(json_object_get(config->j_params, "address-claim"), "region")))) != NULL) {
      json_object_set(j_address, "region", j_value);
    }
    if (json_string_length(json_object_get(json_object_get(config->j_params, "address-claim"), "postal_code")) && (j_value = json_object_get(j_user, json_string_value(json_object_get(json_object_get(config->j_params, "address-claim"), "postal_code")))) != NULL) {
      json_object_set(j_address, "postal_code", j_value);
    }
    if (json_string_length(json_object_get(json_object_get(config->j_params, "address-claim"), "country")) && (j_value = json_object_get(j_user, json_string_value(json_object_get(json_object_get(config->j_params, "address-claim"), "country")))) != NULL) {
      json_object_set(j_address, "country", j_value);
    }
    if (json_object_size(j_address)) {
      j_return = json_pack("{siso}", "result", G_OK, "address", j_address);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      json_decref(j_address);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_address_claim - Error allocating resources for j_address");
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

/**
 * Return the claim value if possible
 */
static json_t * get_claim_value_from_request(struct _oidc_config * config, const char * claim, json_t * j_claim_request, json_t * j_user) {
  json_t * j_element = NULL, * j_user_property, * j_claim_value = NULL, * j_return = NULL, * j_values_element;
  size_t index = 0, index_values = 0;
  char * endptr = NULL;
  int return_claim = 1, tmp_claim;
  long int lvalue;
  
  json_array_foreach(json_object_get(config->j_params, "claims"), index, j_element) {
    if (j_return == NULL && 0 == o_strcmp(json_string_value(json_object_get(j_element, "name")), claim) && json_object_get(j_element, "on-demand") == json_true()) {
      if ((j_user_property = json_object_get(j_user, json_string_value(json_object_get(j_element, "user-property")))) != NULL && (json_string_length(j_user_property) || json_array_size(j_user_property))) {
        if (json_object_get(j_claim_request, "value") != NULL) {
          if (!json_equal(json_object_get(j_claim_request, "value"), j_user_property)) {
            return_claim = 0;
          }
        } else if (json_object_get(j_claim_request, "values") != NULL) {
          tmp_claim = 0;
          json_array_foreach(json_object_get(j_claim_request, "values"), index_values, j_values_element) {
            if (json_equal(j_values_element, j_user_property)) {
              tmp_claim = 1;
              break;
            }
          }
          if (!tmp_claim) {
            return_claim = 0;
          }
        } else if (j_claim_request != json_null()) {
          return_claim = 0;
        }
      } else {
        return_claim = 0;
      }
      if (return_claim) {
        if (json_is_string(j_user_property)) {
          if (0 == o_strcmp("boolean", json_string_value(json_object_get(j_element, "type")))) {
            if (0 == o_strcmp(json_string_value(j_user_property), json_string_value(json_object_get(j_element, "boolean-value-true")))) {
              j_claim_value = json_true();
            } else if (0 == o_strcmp(json_string_value(j_user_property), json_string_value(json_object_get(j_element, "boolean-value-false")))) {
              j_claim_value = json_false();
            }
          } else if (0 == o_strcmp("number", json_string_value(json_object_get(j_element, "type")))) {
            endptr = NULL;
            lvalue = strtol(json_string_value(j_user_property), &endptr, 10);
            if (!(*endptr)) {
              j_claim_value = json_integer(lvalue);
            }
          } else {
            j_claim_value = json_incref(j_user_property);
          }
        } else {
          j_claim_value = json_array();
          json_array_foreach(j_user_property, index_values, j_values_element) {
            if (0 == o_strcmp("boolean", json_string_value(json_object_get(j_element, "type")))) {
              if (0 == o_strcmp(json_string_value(j_values_element), json_string_value(json_object_get(j_element, "boolean-value-true")))) {
                json_array_append(j_claim_value, json_true());
              } else if (0 == o_strcmp(json_string_value(j_values_element), json_string_value(json_object_get(j_element, "boolean-value-false")))) {
                json_array_append(j_claim_value, json_false());
              }
            } else if (0 == o_strcmp("number", json_string_value(json_object_get(j_element, "type")))) {
              endptr = NULL;
              lvalue = strtol(json_string_value(j_values_element), &endptr, 10);
              if (!(*endptr)) {
                json_array_append_new(j_claim_value, json_integer(lvalue));
              }
            } else {
              json_array_append(j_claim_value, j_values_element);
            }
          }
        }
        if (j_claim_value != NULL) {
          j_return = json_pack("{sisO}", "result", G_OK, "claim", j_claim_value);
          json_decref(j_claim_value);
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_PARAM);
        }
        break;
      }
    }
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

/**
 * build a userinfo in JSON format
 */
static json_t * get_userinfo(struct _oidc_config * config, const char * sub, json_t * j_user, json_t * j_claims_request, const char * scopes) {
  json_t * j_userinfo = json_pack("{ss}", "sub", sub), * j_claim = NULL, * j_user_property, * j_address, * j_scope, * j_claim_request = NULL, * j_claim_value, * j_value = NULL;
  char ** scopes_array = NULL, * endptr;
  const char * claim = NULL;
  long int lvalue;
  size_t index = 0, index_scope = 0, index_value = 0;
  
  // Append name if mandatory
  if (0 == o_strcmp("mandatory", json_string_value(json_object_get(config->j_params, "name-claim")))) {
    if (json_object_get(j_user, "name") != NULL) {
      json_object_set(j_userinfo, "name", json_object_get(j_user, "name"));
    }
  }
  // Append e-mail if mandatory
  if (0 == o_strcmp("mandatory", json_string_value(json_object_get(config->j_params, "email-claim")))) {
    if (json_object_get(j_user, "email") != NULL) {
      json_object_set(j_userinfo, "email", json_object_get(j_user, "email"));
    }
  }
  
  // Append address if mandatory
  if (0 == o_strcmp("mandatory", json_string_value(json_object_get(json_object_get(config->j_params, "address-claim"), "type")))) {
    j_address = get_address_claim(config, j_user);
    if (check_result_value(j_address, G_OK)) {
      json_object_set(j_userinfo, "address", json_object_get(j_address, "address"));
    } else if (!check_result_value(j_address, G_ERROR_NOT_FOUND)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_userinfo - Error get_address_claim");
    }
    json_decref(j_address);
  }
  
  // Append claims request
  if (j_claims_request != NULL) {
    json_object_foreach(j_claims_request, claim, j_claim_request) {
      // Append name if on demand
      if (0 == o_strcmp("on-demand", json_string_value(json_object_get(config->j_params, "name-claim")))) {
        if (json_object_get(j_user, "name") != NULL) {
          json_object_set(j_userinfo, "name", json_object_get(j_user, "name"));
        }
      }
      // Append e-mail if on demand
      if (0 == o_strcmp("on-demand", json_string_value(json_object_get(config->j_params, "email-claim")))) {
        if (json_object_get(j_user, "email") != NULL) {
          json_object_set(j_userinfo, "email", json_object_get(j_user, "email"));
        }
      }
      if (0 == o_strcmp("address", claim)) {
        if (0 == o_strcmp("on-demand", json_string_value(json_object_get(json_object_get(config->j_params, "address-claim"), "type")))) {
          j_address = get_address_claim(config, j_user);
          if (check_result_value(j_address, G_OK)) {
            json_object_set(j_userinfo, "address", json_object_get(j_address, "address"));
          } else if (!check_result_value(j_address, G_ERROR_NOT_FOUND)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_userinfo - Error get_address_claim");
          }
          json_decref(j_address);
        }
      } else {
        j_claim_value = get_claim_value_from_request(config, claim, j_claim_request, j_user);
        if (check_result_value(j_claim_value, G_OK)) {
          json_object_set(j_userinfo, claim, json_object_get(j_claim_value, "claim"));
        }
        json_decref(j_claim_value);
      }
    }
  }
  
  // Append scopes claims
  if (scopes == NULL || split_string(scopes, " ", &scopes_array)) {
    json_array_foreach(json_object_get(config->j_params, "name-claim-scope"), index, j_scope) {
      if (string_array_has_value((const char **)scopes_array, json_string_value(j_scope))) {
        if (json_object_get(j_user, "name") != NULL) {
          json_object_set(j_userinfo, "name", json_object_get(j_user, "name"));
        }
      }
    }
    json_array_foreach(json_object_get(config->j_params, "email-claim-scope"), index, j_scope) {
      if (string_array_has_value((const char **)scopes_array, json_string_value(j_scope))) {
        if (json_object_get(j_user, "email") != NULL) {
          json_object_set(j_userinfo, "email", json_object_get(j_user, "email"));
        }
      }
    }
    json_array_foreach(json_object_get(config->j_params, "claims"), index, j_claim) {
      if (json_object_get(j_userinfo, json_string_value(json_object_get(j_claim, "name"))) == NULL) {
        json_array_foreach(json_object_get(j_claim, "scope"), index_scope, j_scope) {
          if (string_array_has_value((const char **)scopes_array, json_string_value(j_scope))) {
            j_user_property = json_object_get(j_user, json_string_value(json_object_get(j_claim, "user-property")));
            if (json_string_length(j_user_property)) {
              if (0 == o_strcmp("boolean", json_string_value(json_object_get(j_claim, "type")))) {
                if (0 == o_strcmp(json_string_value(j_user_property), json_string_value(json_object_get(j_claim, "boolean-value-true")))) {
                  json_object_set(j_userinfo, json_string_value(json_object_get(j_claim, "name")), json_true());
                } else if (0 == o_strcmp(json_string_value(j_user_property), json_string_value(json_object_get(j_claim, "boolean-value-false")))) {
                  json_object_set(j_userinfo, json_string_value(json_object_get(j_claim, "name")), json_false());
                }
              } else if (0 == o_strcmp("number", json_string_value(json_object_get(j_claim, "type")))) {
                endptr = NULL;
                lvalue = strtol(json_string_value(j_user_property), &endptr, 10);
                if (!(*endptr)) {
                  json_object_set_new(j_userinfo, json_string_value(json_object_get(j_claim, "name")), json_integer(lvalue));
                }
              } else {
                json_object_set(j_userinfo, json_string_value(json_object_get(j_claim, "name")), j_user_property);
              }
            } else if (json_array_size(j_user_property)) {
              json_object_set_new(j_userinfo, json_string_value(json_object_get(j_claim, "name")), json_array());
              json_array_foreach(j_user_property, index_value, j_value) {
                if (0 == o_strcmp("boolean", json_string_value(json_object_get(j_claim, "type")))) {
                  if (0 == o_strcmp(json_string_value(j_value), json_string_value(json_object_get(j_claim, "boolean-value-true")))) {
                    json_array_append(json_object_get(j_userinfo, json_string_value(json_object_get(j_claim, "name"))), json_true());
                  } else if (0 == o_strcmp(json_string_value(j_value), json_string_value(json_object_get(j_claim, "boolean-value-false")))) {
                    json_array_append(json_object_get(j_userinfo, json_string_value(json_object_get(j_claim, "name"))), json_false());
                  }
                } else if (0 == o_strcmp("number", json_string_value(json_object_get(j_claim, "type")))) {
                  endptr = NULL;
                  lvalue = strtol(json_string_value(j_value), &endptr, 10);
                  if (!(*endptr)) {
                    json_array_append_new(json_object_get(j_userinfo, json_string_value(json_object_get(j_claim, "name"))), json_integer(lvalue));
                  }
                } else {
                  json_array_append(json_object_get(j_userinfo, json_string_value(json_object_get(j_claim, "name"))), j_value);
                }
              }
            }
          }
        }
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_userinfo - Error split_string scopes");
  }
  
  // Append mandatory claims
  json_array_foreach(json_object_get(config->j_params, "claims"), index, j_claim) {
    if (json_object_get(j_claim, "mandatory") == json_true()) {
      j_user_property = json_object_get(j_user, json_string_value(json_object_get(j_claim, "user-property")));
      if (json_string_length(j_user_property)) {
        if (0 == o_strcmp("boolean", json_string_value(json_object_get(j_claim, "type")))) {
          if (0 == o_strcmp(json_string_value(j_user_property), json_string_value(json_object_get(j_claim, "boolean-value-true")))) {
            json_object_set(j_userinfo, json_string_value(json_object_get(j_claim, "name")), json_true());
          } else if (0 == o_strcmp(json_string_value(j_user_property), json_string_value(json_object_get(j_claim, "boolean-value-false")))) {
            json_object_set(j_userinfo, json_string_value(json_object_get(j_claim, "name")), json_false());
          }
        } else if (0 == o_strcmp("number", json_string_value(json_object_get(j_claim, "type")))) {
          endptr = NULL;
          lvalue = strtol(json_string_value(j_user_property), &endptr, 10);
          if (!(*endptr)) {
            json_object_set_new(j_userinfo, json_string_value(json_object_get(j_claim, "name")), json_integer(lvalue));
          }
        } else {
          json_object_set(j_userinfo, json_string_value(json_object_get(j_claim, "name")), j_user_property);
        }
      } else if (json_array_size(j_user_property)) {
        json_object_set_new(j_userinfo, json_string_value(json_object_get(j_claim, "name")), json_array());
        json_array_foreach(j_user_property, index_value, j_value) {
          if (0 == o_strcmp("boolean", json_string_value(json_object_get(j_claim, "type")))) {
            if (0 == o_strcmp(json_string_value(j_value), json_string_value(json_object_get(j_claim, "boolean-value-true")))) {
              json_array_append(json_object_get(j_userinfo, json_string_value(json_object_get(j_claim, "name"))), json_true());
            } else if (0 == o_strcmp(json_string_value(j_value), json_string_value(json_object_get(j_claim, "boolean-value-false")))) {
              json_array_append(json_object_get(j_userinfo, json_string_value(json_object_get(j_claim, "name"))), json_false());
            }
          } else if (0 == o_strcmp("number", json_string_value(json_object_get(j_claim, "type")))) {
            endptr = NULL;
            lvalue = strtol(json_string_value(j_value), &endptr, 10);
            if (!(*endptr)) {
              json_array_append_new(json_object_get(j_userinfo, json_string_value(json_object_get(j_claim, "name"))), json_integer(lvalue));
            }
          } else {
            json_array_append(json_object_get(j_userinfo, json_string_value(json_object_get(j_claim, "name"))), j_value);
          }
        }
      }
    }
  }
  free_string_array(scopes_array);
  
  return j_userinfo;
}

/**
 * Return the id_token_hash of the last id_token provided to the client for the user
 */
static json_t * get_last_id_token(struct _oidc_config * config, const char * username, const char * client_id) {
  json_t * j_query, * j_result = NULL, * j_return;
  int res;
  
  j_query = json_pack("{sss[sss]s{ssssss}sssi}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_ID_TOKEN,
                      "columns",
                        "gpoi_authorization_type AS authorization_type",
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpoi_issued_at) AS issued_at", "gpoi_issued_at AS issued_at", "EXTRACT(EPOCH FROM gpoi_issued_at)::integer AS issued_at"),
                        "gpoi_hash AS token_hash",
                      "where",
                        "gpoi_plugin_name",
                        config->name,
                        "gpoi_username",
                        username,
                        "gpoi_client_id",
                        client_id,
                      "order_by",
                      "gpoi_id DESC",
                      "limit",
                      1);
  res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    if (json_array_size(j_result)) {
      j_return = json_pack("{sisO}", "result", G_OK, "id_token", json_array_get(j_result, 0));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_last_id_token - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * Store a signature of the id_token in the database
 */
static int serialize_id_token(struct _oidc_config * config, uint auth_type, const char * id_token, const char * username, const char * client_id, time_t now, const char * issued_for, const char * user_agent) {
  json_t * j_query;
  int res, ret;
  char * issued_at_clause, * id_token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, id_token);
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_id_token - Error pthread_mutex_lock");
    ret = G_ERROR;
  } else {
    if (issued_for != NULL && now > 0 && id_token_hash != NULL) {
      if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
        issued_at_clause = msprintf("FROM_UNIXTIME(%u)", (now));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        issued_at_clause = msprintf("TO_TIMESTAMP(%u)", (now));
      } else { // HOEL_DB_TYPE_SQLITE
        issued_at_clause = msprintf("%u", (now));
      }
      j_query = json_pack("{sss{sssisosos{ss}ssssss}}",
                          "table",
                          GLEWLWYD_PLUGIN_OIDC_TABLE_ID_TOKEN,
                          "values",
                            "gpoi_plugin_name",
                            config->name,
                            "gpoi_authorization_type",
                            auth_type,
                            "gpoi_username",
                            username!=NULL?json_string(username):json_null(),
                            "gpoi_client_id",
                            client_id!=NULL?json_string(client_id):json_null(),
                            "gpoi_issued_at",
                              "raw",
                              issued_at_clause,
                            "gpoi_issued_for",
                            issued_for,
                            "gpoi_user_agent",
                            user_agent!=NULL?user_agent:"",
                            "gpoi_hash",
                            id_token_hash);
      o_free(issued_at_clause);
      res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_id_token - Error executing j_query");
        ret = G_ERROR_DB;
      }
    } else {
      ret = G_ERROR_PARAM;
    }
    pthread_mutex_unlock(&config->insert_lock);
    o_free(id_token_hash);
  }
  return ret;
}

/**
 * Builds an id_token from the given parameters
 */
static char * generate_id_token(struct _oidc_config * config, const char * username, json_t * j_user, json_t * j_client, time_t now, time_t auth_time, const char * nonce, json_t * j_amr, const char * access_token, const char * code, const char * scopes, json_t * j_claims_request) {
  jwt_t * jwt = NULL;
  jwk_t * jwk = NULL;
  char * token = NULL, at_hash_encoded[128] = {0}, c_hash_encoded[128] = {0}, * sub = get_sub(config, username, j_client);
  unsigned char at_hash[128] = {0}, c_hash[128] = {0};
  json_t * j_user_info;
  size_t at_hash_len = 128, at_hash_encoded_len = 0, c_hash_len = 128, c_hash_encoded_len = 0;
  int alg = GNUTLS_DIG_UNKNOWN;
  gnutls_datum_t hash_data;
  const char * sign_kid = json_string_value(json_object_get(config->j_params, "client-sign_kid-parameter"));
  int key_size = 0;
  
  if (sub != NULL) {
    if ((jwt = r_jwt_copy(config->jwt_sign)) != NULL) {
      if (j_client != NULL) {
        if (json_string_length(json_object_get(j_client, sign_kid))) {
          jwk = r_jwks_get_by_kid(config->jwt_sign->jwks_privkey_sign, json_string_value(json_object_get(j_client, sign_kid)));
          key_size = get_key_size_from_alg(r_jwk_get_property_str(jwk, "alg"));
        } else {
          jwk = r_jwk_copy(config->jwk_sign_default);
          key_size = config->jwt_key_size;
        }
      } else {
        jwk = r_jwk_copy(config->jwk_sign_default);
        key_size = config->jwt_key_size;
      }
      if (key_size) {
        if ((j_user_info = get_userinfo(config, sub, j_user, j_claims_request, scopes)) != NULL) {
          json_object_set(j_user_info, "iss", json_object_get(config->j_params, "iss"));
          json_object_set(j_user_info, "aud", json_object_get(j_client, "client_id"));
          json_object_set_new(j_user_info, "exp", json_integer(now + config->access_token_duration));
          json_object_set_new(j_user_info, "iat", json_integer(now));
          json_object_set_new(j_user_info, "auth_time", json_integer(auth_time));
          json_object_set(j_user_info, "azp", json_object_get(j_client, "client_id"));
          if (o_strlen(nonce)) {
            json_object_set_new(j_user_info, "nonce", json_string(nonce));
          }
          if (j_amr != NULL && json_array_size(j_amr)) {
            json_object_set(j_user_info, "amr", j_amr);
          }
          if (access_token != NULL) {
            // Hash access_token using the key size for the hash size (SHA style of course!)
            // take the half left of the has, then encode in base64-url it
            if (key_size == 256) alg = GNUTLS_DIG_SHA256;
            else if (key_size == 384) alg = GNUTLS_DIG_SHA384;
            else if (key_size == 512) alg = GNUTLS_DIG_SHA512;
            if (alg != GNUTLS_DIG_UNKNOWN) {
              hash_data.data = (unsigned char*)access_token;
              hash_data.size = o_strlen(access_token);
              if (gnutls_fingerprint(alg, &hash_data, at_hash, &at_hash_len) == GNUTLS_E_SUCCESS) {
                if (o_base64url_encode(at_hash, at_hash_len/2, (unsigned char *)at_hash_encoded, &at_hash_encoded_len)) {
                  json_object_set_new(j_user_info, "at_hash", json_stringn(at_hash_encoded, at_hash_encoded_len));
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "generate_id_token - Error o_base64url_encode at_hash");
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "generate_id_token - Error gnutls_fingerprint at_hash");
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "generate_id_token - Error digest algorithm size '%d' not supported at_hash", config->jwt_key_size);
            }
          }
          if (code != NULL) {
            // Hash access_token using the key size for the hash size (SHA style of course!)
            // take the half left of the has, then encode in base64-url it
            if (key_size == 256) alg = GNUTLS_DIG_SHA256;
            else if (key_size == 384) alg = GNUTLS_DIG_SHA384;
            else if (key_size == 512) alg = GNUTLS_DIG_SHA512;
            if (alg != GNUTLS_DIG_UNKNOWN) {
              hash_data.data = (unsigned char*)code;
              hash_data.size = o_strlen(code);
              if (gnutls_fingerprint(alg, &hash_data, c_hash, &c_hash_len) == GNUTLS_E_SUCCESS) {
                if (o_base64url_encode(c_hash, c_hash_len/2, (unsigned char *)c_hash_encoded, &c_hash_encoded_len)) {
                  json_object_set_new(j_user_info, "c_hash", json_stringn(c_hash_encoded, c_hash_encoded_len));
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "generate_id_token - Error o_base64url_encode c_hash");
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "generate_id_token - Error gnutls_fingerprint c_hash");
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "generate_id_token - Error digest algorithm size '%d' not supported c_hash", config->jwt_key_size);
            }
          }
          //jwt_add_grant(jwt, "acr", "plop"); // TODO?
          if (r_jwt_set_full_claims_json_t(jwt, j_user_info) == RHN_OK) {
            token = r_jwt_serialize_signed(jwt, jwk, 0);
            if (token == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_id_token - oidc - Error r_jwt_serialize_signed");
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_id_token - oidc - Error jwt_add_grants_json");
          }
          json_decref(j_user_info);
          r_jwk_free(jwk);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_id_token - oidc - Error get_userinfo");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_id_token - oidc - Error key_size");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_id_token - oidc - Error r_jwt_copy");
    }
    r_jwt_free(jwt);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_id_token - oidc - Error get_sub");
  }
  o_free(sub);
  return token;
}

/**
 * Store a signature of the acces token in the database
 */
static int serialize_access_token(struct _oidc_config * config, uint auth_type, json_int_t gpor_id, const char * username, const char * client_id, const char * scope_list, time_t now, const char * issued_for, const char * user_agent, const char * access_token, const char * jti) {
  json_t * j_query, * j_last_id;
  int res, ret, i;
  char * issued_at_clause, ** scope_array = NULL, * access_token_hash = NULL;
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error pthread_mutex_lock");
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
        j_query = json_pack("{sss{sssisososos{ss}ssssssss}}",
                            "table",
                            GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN,
                            "values",
                              "gpoa_plugin_name",
                              config->name,
                              "gpoa_authorization_type",
                              auth_type,
                              "gpor_id",
                              gpor_id?json_integer(gpor_id):json_null(),
                              "gpoa_username",
                              username!=NULL?json_string(username):json_null(),
                              "gpoa_client_id",
                              client_id!=NULL?json_string(client_id):json_null(),
                              "gpoa_issued_at",
                                "raw",
                                issued_at_clause,
                              "gpoa_issued_for",
                              issued_for,
                              "gpoa_user_agent",
                              user_agent!=NULL?user_agent:"",
                              "gpoa_token_hash",
                              access_token_hash,
                              "gpoa_jti",
                              jti);
        o_free(issued_at_clause);
        res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
          if (j_last_id != NULL) {
            if (split_string(scope_list, " ", &scope_array) > 0) {
              j_query = json_pack("{sss[]}",
                                  "table",
                                  GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN_SCOPE,
                                  "values");
              if (j_query != NULL) {
                for (i=0; scope_array[i] != NULL; i++) {
                  json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOss}", "gpoa_id", j_last_id, "gpoas_scope", scope_array[i]));
                }
                res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
                json_decref(j_query);
                if (res == H_OK) {
                  ret = G_OK;
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error executing j_query (2)");
                  ret = G_ERROR_DB;
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error json_pack");
                ret = G_ERROR;
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error split_string");
              ret = G_ERROR;
            }
            free_string_array(scope_array);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error h_last_insert_id");
            ret = G_ERROR_DB;
          }
          json_decref(j_last_id);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error executing j_query (1)");
          ret = G_ERROR_DB;
        }
      } else {
        ret = G_ERROR_PARAM;
      }
      o_free(access_token_hash);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_access_token - Error glewlwyd_callback_generate_hash");
      ret = G_ERROR;
    }
    pthread_mutex_unlock(&config->insert_lock);
  }
  return ret;
}

/**
 * Builds an acces token from the given parameters
 */
static char * generate_access_token(struct _oidc_config * config, const char * username, json_t * j_client, json_t * j_user, const char * scope_list, json_t * j_claims, time_t now, char * jti) {
  jwt_t * jwt = NULL;
  jwk_t * jwk = NULL;
  char * token = NULL, * property = NULL, * sub = get_sub(config, username, j_client);
  json_t * j_element = NULL, * j_value;
  size_t index = 0, index_p = 0;
  const char * sign_kid = json_string_value(json_object_get(config->j_params, "client-sign_kid-parameter"));
  
  if (sub != NULL) {
    if ((jwt = r_jwt_copy(config->jwt_sign)) != NULL) {
      rand_string_nonce(jti, OIDC_JTI_LENGTH);
      r_jwt_set_claim_str_value(jwt, "iss", json_string_value(json_object_get(config->j_params, "iss")));
      if (j_client != NULL) {
        r_jwt_set_claim_str_value(jwt, "aud", json_string_value(json_object_get(j_client, "client_id")));
        r_jwt_set_claim_str_value(jwt, "client_id", json_string_value(json_object_get(j_client, "client_id")));
        if (json_string_length(json_object_get(j_client, sign_kid))) {
          jwk = r_jwks_get_by_kid(config->jwt_sign->jwks_privkey_sign, json_string_value(json_object_get(j_client, sign_kid)));
        } else {
          jwk = r_jwk_copy(config->jwk_sign_default);
        }
      } else {
        jwk = r_jwk_copy(config->jwk_sign_default);
      }
      r_jwt_set_header_str_value(jwt, "typ", "at+jwt");
      r_jwt_set_claim_str_value(jwt, "sub", sub);
      r_jwt_set_claim_str_value(jwt, "jti", jti);
      r_jwt_set_claim_str_value(jwt, "type", "access_token");
      r_jwt_set_claim_int_value(jwt, "iat", now);
      r_jwt_set_claim_int_value(jwt, "exp", (now + config->access_token_duration));
      r_jwt_set_claim_int_value(jwt, "nbf", now);
      if (scope_list != NULL) {
        r_jwt_set_claim_str_value(jwt, "scope", scope_list);
      }
      if (j_claims != NULL) {
        r_jwt_set_claim_json_t_value(jwt, "claims", j_claims);
      }
      if (json_object_get(config->j_params, "additional-parameters") != NULL && j_user != NULL) {
        json_array_foreach(json_object_get(config->j_params, "additional-parameters"), index, j_element) {
          if (json_is_string(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter")))) && json_string_length(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))))) {
            r_jwt_set_claim_str_value(jwt, json_string_value(json_object_get(j_element, "token-parameter")), json_string_value(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter")))));
          } else if (json_is_array(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))))) {
            json_array_foreach(json_object_get(j_user, json_string_value(json_object_get(j_element, "user-parameter"))), index_p, j_value) {
              property = mstrcatf(property, ",%s", json_string_value(j_value));
            }
            if (o_strlen(property)) {
              r_jwt_set_claim_str_value(jwt, json_string_value(json_object_get(j_element, "token-parameter")), property+1); // Skip first ','
            } else {
              r_jwt_set_claim_str_value(jwt, json_string_value(json_object_get(j_element, "token-parameter")), "");
            }
            o_free(property);
            property = NULL;
          }
        }
      }
      if (jwk != NULL) {
        if ((token = r_jwt_serialize_signed(jwt, jwk, 0)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_access_token - oidc - Error r_jwt_serialize_signed");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_access_token - oidc - Error no jwk to sign");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_access_token - oidc - Error r_jwt_copy");
    }
    r_jwt_free(jwt);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_access_token - oidc - Error get_sub");
  }
  o_free(sub);
  r_jwk_free(jwk);
  return token;
}

/**
 * Store a signature of the refresh token in the database
 */
static json_t * serialize_refresh_token(struct _oidc_config * config, uint auth_type, json_int_t gpoc_id, const char * username, const char * client_id, const char * scope_list, time_t now, json_int_t duration, uint rolling, json_t * j_claims_request, const char * token, const char * issued_for, const char * user_agent) {
  char * token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token);
  json_t * j_query, * j_return, * j_last_id;
  int res, i;
  char * issued_at_clause, * expires_at_clause, * last_seen_clause, ** scope_array = NULL, * str_claims_request = NULL;
  
  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error pthread_mutex_lock");
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
        expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)duration));
      } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
        expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)duration ));
      } else { // HOEL_DB_TYPE_SQLITE
        expires_at_clause = msprintf("%u", (now + (unsigned int)duration));
      }
      if (j_claims_request != NULL) {
        if ((str_claims_request = json_dumps(j_claims_request, JSON_COMPACT)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error dumping JSON claims request");
        }
      }
      j_query = json_pack_ex(&error, 0, "{sss{ss si so ss so s{ss} s{ss} s{ss} sI si ss ss ss ss}}",
                          "table",
                          GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                          "values",
                            "gpor_plugin_name",
                            config->name,
                            "gpor_authorization_type",
                            auth_type,
                            "gpoc_id",
                            gpoc_id?json_integer(gpoc_id):json_null(),
                            "gpor_username",
                            username,
                            "gpor_client_id",
                            client_id!=NULL?json_string(client_id):json_null(),
                            "gpor_issued_at",
                              "raw",
                              issued_at_clause,
                            "gpor_last_seen",
                              "raw",
                              last_seen_clause,
                            "gpor_expires_at",
                              "raw",
                              expires_at_clause,
                            "gpor_duration",
                            duration,
                            "gpor_rolling_expiration",
                            rolling,
                            "gpor_claims_request",
                            str_claims_request!=NULL?str_claims_request:"",
                            "gpor_token_hash",
                            token_hash,
                            "gpor_issued_for",
                            issued_for,
                            "gpor_user_agent",
                            user_agent!=NULL?user_agent:"");
      o_free(issued_at_clause);
      o_free(expires_at_clause);
      o_free(last_seen_clause);
      o_free(str_claims_request);
      res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        j_last_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
        if (j_last_id != NULL) {
          if (split_string(scope_list, " ", &scope_array) > 0) {
            j_query = json_pack("{sss[]}",
                                "table",
                                GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN_SCOPE,
                                "values");
            if (j_query != NULL) {
              for (i=0; scope_array[i] != NULL; i++) {
                json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOss}", "gpor_id", j_last_id, "gpors_scope", scope_array[i]));
              }
              res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
              json_decref(j_query);
              if (res == H_OK) {
                j_return = json_pack("{sisO}", "result", G_OK, "gpor_id", j_last_id);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error executing j_query (2)");
                j_return = json_pack("{si}", "result", G_ERROR_DB);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error json_pack");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error split_string");
            j_return = json_pack("{si}", "result", G_ERROR);
          }
          free_string_array(scope_array);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error h_last_insert_id");
          j_return = json_pack("{si}", "result", G_ERROR_DB);
        }
        json_decref(j_last_id);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc serialize_refresh_token - Error executing j_query (1)");
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

/**
 * Builds an refresh token from the given parameters
 */
static char * generate_refresh_token() {
  char * token = o_malloc((OIDC_REFRESH_TOKEN_LENGTH+1)*sizeof(char));
  
  if (token != NULL) {
    if (rand_string(token, OIDC_REFRESH_TOKEN_LENGTH) == NULL) {
      o_free(token);
      token = NULL;
    }
  }
  return token;
}

/**
 * Return true if the auth type is enabled in this plugin instance
 */
static int is_authorization_type_enabled(struct _oidc_config * config, uint authorization_type) {
  return (authorization_type <= 7)?config->auth_type_enabled[authorization_type]:0;
}

/**
 * Verify if a client is valid without checking its secret
 */
static json_t * check_client_valid_without_secret(struct _oidc_config * config, const char * client_id, const char * redirect_uri, unsigned short authorization_type, const char * ip_source) {
  json_t * j_client, * j_element = NULL, * j_return;
  int uri_found = 0, authorization_type_enabled;
  size_t index = 0;

  j_client = config->glewlwyd_config->glewlwyd_plugin_callback_get_client(config->glewlwyd_config, client_id);
  if (check_result_value(j_client, G_OK)) {
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
      if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE_FLAG && 0 == o_strcmp(json_string_value(j_element), "code")) {
        authorization_type_enabled = 1;
      } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_TOKEN_FLAG && 0 == o_strcmp(json_string_value(j_element), "token")) {
        authorization_type_enabled = 1;
      } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN_FLAG && 0 == o_strcmp(json_string_value(j_element), "id_token")) {
        authorization_type_enabled = 1;
      } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_NONE_FLAG && 0 == o_strcmp(json_string_value(j_element), "none")) {
        authorization_type_enabled = 1;
      } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN_FLAG && 0 == o_strcmp(json_string_value(j_element), "refresh_token")) {
        authorization_type_enabled = 1;
        uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
      } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS_FLAG && 0 == o_strcmp(json_string_value(j_element), "client_credentials")) {
        authorization_type_enabled = 1;
        uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
      } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS_FLAG && 0 == o_strcmp(json_string_value(j_element), "password")) {
        authorization_type_enabled = 1;
        uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
      } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_DELETE_TOKEN_FLAG && 0 == o_strcmp(json_string_value(j_element), "delete_token")) {
        authorization_type_enabled = 1;
        uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
      }
    }
    if (!uri_found) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid_without_secret - Error, redirect_uri '%s' is invalid for the client '%s', origin: %s", redirect_uri, client_id, ip_source);
    }
    if (!authorization_type_enabled) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid_without_secret - Error, authorization type %d is not enabled for the client '%s', origin: %s", authorization_type, client_id, ip_source);
    }
    if (uri_found && authorization_type_enabled) {
      j_return = json_pack("{sisO}", "result", G_OK, "client", json_object_get(j_client, "client"));
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid_without_secret - Error, client '%s' is invalid, origin: %s", client_id, ip_source);
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  json_decref(j_client);
  return j_return;
}

/**
 * Verify if a client is valid
 */
static json_t * check_client_valid(struct _oidc_config * config, const char * client_id, const char * client_header_login, const char * client_header_password, const char * client_post_login, const char * client_post_password, const char * redirect_uri, unsigned short authorization_type, int implicit_flow, const char * ip_source) {
  json_t * j_client, * j_element = NULL, * j_return;
  int uri_found = 0, authorization_type_enabled;
  size_t index = 0;
  const char * client_password = NULL;
  
  if (client_id == NULL) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error client_id is NULL, origin: %s", ip_source);
    return json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (client_header_login != NULL && 0 != o_strcmp(client_header_login, client_id)) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error, client_id specified is different from client_id in the basic auth header, origin: %s", ip_source);
    return json_pack("{si}", "result", G_ERROR_PARAM);
  } else if (client_post_login != NULL && 0 != o_strcmp(client_post_login, client_id)) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error, client_id specified is different from client_id in the basic auth header, origin: %s", ip_source);
    return json_pack("{si}", "result", G_ERROR_PARAM);
  }
  if (client_header_login != NULL) {
    client_password = client_header_password;
  } else if (client_post_login != NULL) {
    client_password = client_post_password;
  }
  j_client = config->glewlwyd_config->glewlwyd_callback_check_client_valid(config->glewlwyd_config, client_id, client_password);
  if (check_result_value(j_client, G_OK)) {
    if (!implicit_flow && client_password == NULL && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error, confidential client must be authentified with its password, origin: %s", ip_source);
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
        if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE_FLAG && 0 == o_strcmp(json_string_value(j_element), "code")) {
          authorization_type_enabled = 1;
        } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_TOKEN_FLAG && 0 == o_strcmp(json_string_value(j_element), "token")) {
          authorization_type_enabled = 1;
        } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN_FLAG && 0 == o_strcmp(json_string_value(j_element), "id_token")) {
          authorization_type_enabled = 1;
        } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_NONE_FLAG && 0 == o_strcmp(json_string_value(j_element), "none")) {
          authorization_type_enabled = 1;
        } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN_FLAG && 0 == o_strcmp(json_string_value(j_element), "refresh_token")) {
          authorization_type_enabled = 1;
          uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
        } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS_FLAG && 0 == o_strcmp(json_string_value(j_element), "client_credentials")) {
          authorization_type_enabled = 1;
          uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
        } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS_FLAG && 0 == o_strcmp(json_string_value(j_element), "password")) {
          authorization_type_enabled = 1;
          uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
        } else if (authorization_type & GLEWLWYD_AUTHORIZATION_TYPE_DELETE_TOKEN_FLAG && 0 == o_strcmp(json_string_value(j_element), "delete_token")) {
          authorization_type_enabled = 1;
          uri_found = 1; // bypass redirect_uri check for client credentials since it's not needed
        }
      }
      if (!uri_found) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error, redirect_uri '%s' is invalid for the client '%s', origin: %s", redirect_uri, client_id, ip_source);
      }
      if (!authorization_type_enabled) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error, authorization type %d is not enabled for the client '%s', origin: %s", authorization_type, client_id, ip_source);
      }
      if (uri_found && authorization_type_enabled) {
        j_return = json_pack("{sisO}", "result", G_OK, "client", json_object_get(j_client, "client"));
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_client_valid - Error, client '%s' is invalid, origin: %s", client_id, ip_source);
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  json_decref(j_client);
  return j_return;
}

/**
 * builds the amr list based on the code
 */
static int set_amr_list_for_code(struct _oidc_config * config, json_int_t gpoc_id, json_t * j_amr) {
  json_t * j_query, * j_element = NULL;
  int ret;
  size_t index = 0;
  
  if (j_amr != NULL) {
    if (json_array_size(j_amr)) {
      j_query = json_pack("{sss[]}", "table", GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SHEME, "values");
      if (j_query != NULL) {
        json_array_foreach(j_amr, index, j_element) {
          json_array_append_new(json_object_get(j_query, "values"), json_pack("{sIsO}", "gpoc_id", gpoc_id, "gpoch_scheme_module", j_element));
        }
        if (h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL) == H_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "set_amr_list_for_code - Error executing j_query (1)");
          ret = G_ERROR_DB;
        }
        json_decref(j_query);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_amr_list_for_code - Error allocating resources for j_query");
        ret = G_ERROR_MEMORY;
      }
    } else {
      j_query = json_pack("{sss{sIss}}", "table", GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SHEME, "values", "gpoc_id", gpoc_id, "gpoch_scheme_module", "session");
      if (h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL) == H_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_amr_list_for_code - Error executing j_query (2)");
        ret = G_ERROR_DB;
      }
      json_decref(j_query);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "set_amr_list_for_code - Error param %s", json_dumps(j_amr, JSON_ENCODE_ANY));
    ret = G_ERROR_PARAM;
  }
  return ret;
}

/**
 * Builds an authorization code from the given parameters
 * Store a signature of the authorization code in the database
 */
static char * generate_authorization_code(struct _oidc_config * config, const char * username, const char * client_id, const char * scope_list, const char * redirect_uri, const char * issued_for, const char * user_agent, const char * nonce, json_t * j_amr, json_t * j_claims, int auth_type, const char * code_challenge) {
  char * code = NULL, * code_hash = NULL, * expiration_clause, ** scope_array = NULL, * str_claims = NULL;
  json_t * j_query, * j_code_id;
  int res, i;
  time_t now;

  if (pthread_mutex_lock(&config->insert_lock)) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error pthread_mutex_lock");
  } else {
    code = o_malloc(33*sizeof(char));
    if (code != NULL) {
      if (rand_string_nonce(code, 32) != NULL) {
        code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code);
        if (code_hash != NULL) {
          if (j_claims != NULL) {
            str_claims = json_dumps(j_claims, JSON_COMPACT);
            if (str_claims == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "oidc generate_authorization_code - Error dumping claims");
            }
          }
          time(&now);
          if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
            expiration_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)config->code_duration ));
          } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
            expiration_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)config->code_duration ));
          } else { // HOEL_DB_TYPE_SQLITE
            expiration_clause = msprintf("%u", (now + (unsigned int)config->code_duration ));
          }
          j_query = json_pack("{sss{sssssssssssssssssssis{ss}ss}}",
                              "table",
                              GLEWLWYD_PLUGIN_OIDC_TABLE_CODE,
                              "values",
                                "gpoc_plugin_name",
                                config->name,
                                "gpoc_username",
                                username,
                                "gpoc_client_id",
                                client_id,
                                "gpoc_redirect_uri",
                                redirect_uri,
                                "gpoc_code_hash",
                                code_hash,
                                "gpoc_issued_for",
                                issued_for,
                                "gpoc_user_agent",
                                user_agent!=NULL?user_agent:"",
                                "gpoc_nonce",
                                nonce!=NULL?nonce:"",
                                "gpoc_claims_request",
                                str_claims!=NULL?str_claims:"",
                                "gpoc_authorization_type",
                                auth_type,
                                "gpoc_expires_at",
                                  "raw",
                                  expiration_clause,
                                "gpoc_code_challenge",
                                code_challenge);
          o_free(expiration_clause);
          o_free(str_claims);
          res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
          json_decref(j_query);
          if (res != H_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error executing j_query (1)");
            o_free(code);
            code = NULL;
          } else {
            if (scope_list != NULL) {
              j_code_id = h_last_insert_id(config->glewlwyd_config->glewlwyd_config->conn);
              if (j_code_id != NULL) {
                j_query = json_pack("{sss[]}",
                                    "table",
                                    GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SCOPE,
                                    "values");
                if (split_string(scope_list, " ", &scope_array) > 0) {
                  for (i=0; scope_array[i] != NULL; i++) {
                    json_array_append_new(json_object_get(j_query, "values"), json_pack("{sOss}", "gpoc_id", j_code_id, "gpocs_scope", scope_array[i]));
                  }
                  res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
                  json_decref(j_query);
                  if (res != H_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error executing j_query (2)");
                    o_free(code);
                    code = NULL;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error split_string");
                  o_free(code);
                  code = NULL;
                }
                free_string_array(scope_array);
                if (set_amr_list_for_code(config, json_integer_value(j_code_id), j_amr) != G_OK) {
                  y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error set_amr_list_for_code");
                  o_free(code);
                  code = NULL;
                }
                json_decref(j_code_id);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error h_last_insert_id");
                o_free(code);
                code = NULL;
              }
            }
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error glewlwyd_callback_generate_hash");
          o_free(code);
          code = NULL;
        }
        o_free(code_hash);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error rand_string");
        o_free(code);
        code = NULL;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc generate_authorization_code - Error allocating resources for code");
    }
    pthread_mutex_unlock(&config->insert_lock);
  }

  return code;
}

/**
 *
 * Generates a query string based on url and post parameters of a request
 * Returned value must be o_free'd after use
 *
 */
static char * generate_query_parameters(struct _u_map * map) {
  char * query = NULL, * param, * value;
  const char ** keys;
  int i;
  
  if (map == NULL) {
    return NULL;
  } else {
    if (map != NULL) {
      keys = u_map_enum_keys(map);
      for (i=0; keys[i] != NULL; i++) {
        if (u_map_get(map, keys[i]) != NULL) {
          value = url_encode((char *)u_map_get(map, keys[i]));
          param = msprintf("%s=%s", keys[i], value);
          o_free(value);
          if (query == NULL) {
            query = o_strdup(param);
          } else {
            query = mstrcatf(query, "&%s", param);
          }
          o_free(param);
        } else {
          if (query == NULL) {
            query = o_strdup(keys[i]);
          } else {
            query = mstrcatf(query, "&%s", keys[i]);
          }
        }
      }
    }
  }
  
  return query;
}

/**
 * Return the login url based on the curret context
 */
static char * get_login_url(struct _oidc_config * config, const struct _u_request * request, const char * url, const char * client_id, const char * scope_list, struct _u_map * additional_parameters) {
  char * plugin_url = config->glewlwyd_config->glewlwyd_callback_get_plugin_external_url(config->glewlwyd_config, json_string_value(json_object_get(config->j_params, "name"))),
       * url_params = generate_query_parameters(get_map(request)),
       * url_callback = msprintf("%s/%s?%s", plugin_url, url, url_params),
       * login_url = config->glewlwyd_config->glewlwyd_callback_get_login_url(config->glewlwyd_config, client_id, scope_list, url_callback, additional_parameters);
  o_free(plugin_url);
  o_free(url_params);
  o_free(url_callback);
  return login_url;
}

/**
 * return the scope parameters if set in the parameters
 */
static json_t * get_scope_parameters(struct _oidc_config * config, const char * scope) {
  json_t * j_element = NULL, * j_return = NULL;
  size_t index = 0;
  
  json_array_foreach(json_object_get(config->j_params, "scope"), index, j_element) {
    if (0 == o_strcmp(scope, json_string_value(json_object_get(j_element, "name")))) {
      j_return = json_incref(j_element);
    }
  }
  return j_return;
}

/**
 * disable an authoriation code
 */
static int disable_authorization_code(struct _oidc_config * config, json_int_t gpoc_id) {
  json_t * j_query;
  int res;
  
  j_query = json_pack("{sss{si}s{sssI}}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_CODE,
                      "set",
                        "gpoc_enabled",
                        0,
                      "where",
                        "gpoc_plugin_name",
                        config->name,
                        "gpoc_id",
                        gpoc_id);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    return G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc disable_authorization_code - Error executing j_query");
    return G_ERROR_DB;
  }
}

/**
 * return the amr list based on the code
 */
static json_t * get_amr_list_from_code(struct _oidc_config * config, json_int_t gpoc_id) {
  json_t * j_query, * j_result, * j_return, * j_element = NULL;
  int ret;
  size_t index = 0;
  
  j_query = json_pack("{sss[s]s{sI}}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SHEME,
                      "columns",
                        "gpoch_scheme_module",
                      "where",
                        "gpoc_id",
                        gpoc_id);
  ret = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (ret == H_OK) {
    if (json_array_size(j_result)) {
      j_return = json_pack("{sis[]}", "result", G_OK, "amr");
      if (j_return != NULL) {
        json_array_foreach(j_result, index, j_element) {
          json_array_append(json_object_get(j_return, "amr"), json_object_get(j_element, "gpoch_scheme_module"));
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_amr_list_from_code - Error allocating resources for j_return");
        j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
      }
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_amr_list_from_code - Error executing query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
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
  
  if (json_string_length(json_object_get(j_result_code, "code_challenge"))) {
    if (is_pkce_char_valid(code_verifier)) {
      if (0 == o_strncmp(GLEWLWYD_CODE_CHALLENGE_S256_PREFIX, json_string_value(json_object_get(j_result_code, "code_challenge")), o_strlen(GLEWLWYD_CODE_CHALLENGE_S256_PREFIX))) {
        key_data.data = (unsigned char *)code_verifier;
        key_data.size = o_strlen(code_verifier);
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

static int is_code_challenge_valid(struct _oidc_config * config, const char * code_challenge, const char * code_challenge_method, char * code_challenge_stored) {
  int ret;
  if (o_strlen(code_challenge)) {
    if (json_object_get(config->j_params, "pkce-allowed") == json_true()) {
      if (!o_strlen(code_challenge_method) || 0 == o_strcmp("plain", code_challenge_method)) {
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

/**
 * verify that the auth code is valid
 */
static json_t * validate_authorization_code(struct _oidc_config * config, const char * code, const char * client_id, const char * redirect_uri, const char * code_verifier) {
  char * code_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, code), * expiration_clause = NULL, * scope_list = NULL, * tmp;
  json_t * j_query, * j_result = NULL, * j_result_scope = NULL, * j_return, * j_element = NULL, * j_scope_param;
  int res, has_scope_openid = 0;
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
    j_query = json_pack("{sss[sssss]s{sssssssssis{ssss}}}",
                        "table",
                        GLEWLWYD_PLUGIN_OIDC_TABLE_CODE,
                        "columns",
                          "gpoc_username AS username",
                          "gpoc_nonce AS nonce",
                          "gpoc_claims_request AS claims_request",
                          "gpoc_id",
                          "gpoc_code_challenge AS code_challenge",
                        "where",
                          "gpoc_plugin_name",
                          config->name,
                          "gpoc_client_id",
                          client_id,
                          "gpoc_redirect_uri",
                          redirect_uri,
                          "gpoc_code_hash",
                          code_hash,
                          "gpoc_enabled",
                          1,
                          "gpoc_expires_at",
                            "operator",
                            "raw",
                            "value",
                            expiration_clause);
    o_free(expiration_clause);
    res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        if ((res = validate_code_challenge(json_array_get(j_result, 0), code_verifier)) == G_OK) {
          j_query = json_pack("{sss[s]s{sO}}",
                              "table",
                              GLEWLWYD_PLUGIN_OIDC_TABLE_CODE_SCOPE,
                              "columns",
                                "gpocs_scope AS name",
                              "where",
                                "gpoc_id",
                                json_object_get(json_array_get(j_result, 0), "gpoc_id"));
          res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result_scope, NULL);
          json_decref(j_query);
          if (res == H_OK && json_array_size(j_result_scope) > 0) {
            if (!json_object_set_new(json_array_get(j_result, 0), "scope", json_array())) {
              json_array_foreach(j_result_scope, index, j_element) {
                if (0 == o_strcmp("openid", json_string_value(json_object_get(j_element, "name")))) {
                  has_scope_openid = 1;
                }
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
              json_object_set(json_array_get(j_result, 0), "has-scope-openid", has_scope_openid?json_true():json_false());
              j_return = json_pack("{sisO}", "result", G_OK, "code", json_array_get(j_result, 0));
              o_free(scope_list);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_authorization_code - Error allocating resources for json_array()");
              j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_authorization_code - Error executing j_query (2)");
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
        } else if (res == G_ERROR_UNAUTHORIZED) {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        } else if (res == G_ERROR_PARAM) {
          j_return = json_pack("{si}", "result", G_ERROR_PARAM);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_authorization_code - Error validate_code_challenge");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_result_scope);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_authorization_code - Error executing j_query (1)");
      j_return = json_pack("{si}", "result", G_ERROR_DB);
    }
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_authorization_code - Error glewlwyd_callback_generate_hash");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  o_free(code_hash);
  return j_return;
}

/**
 * Verify that the session is valid based on the client_id and the scope requested
 * The scope list must be at least partially authenticated and granted for the client
 */
static json_t * validate_session_client_scope(struct _oidc_config * config, const struct _u_request * request, const char * client_id, const char * scope) {
  json_t * j_session, * j_grant, * j_return, * j_scope_session, * j_scope_grant = NULL, * j_group = NULL, * j_scheme;
  const char * scope_session, * group = NULL;
  char * scope_filtered = NULL, * tmp;
  size_t index = 0;
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
        json_object_set_new(json_object_get(j_session, "session"), "amr", json_array());
        
        json_object_foreach(json_object_get(json_object_get(j_session, "session"), "scope"), scope_session, j_scope_session) {
          // Evaluate if the scope is granted for the client
          json_array_foreach(json_object_get(json_object_get(j_grant, "grant"), "scope"), index, j_scope_grant) {
            if (0 == o_strcmp(scope_session, json_string_value(json_object_get(j_scope_grant, "name")))) {
              json_object_set(j_scope_session, "granted", json_object_get(j_scope_grant, "granted"));
            }
          }
        
          // Evaluate if the scope is authorized
          if (json_object_get(j_scope_session, "available") == json_true()) {
            if (json_object_get(j_scope_session, "password_required") == json_true() && json_object_get(j_scope_session, "password_authenticated") == json_true()) {
              if (!json_array_has_string(json_object_get(json_object_get(j_session, "session"), "amr"), "password")) {
                json_array_append_new(json_object_get(json_object_get(j_session, "session"), "amr"), json_string("password"));
              }
            }
            if (json_object_get(j_scope_session, "password_required") == json_true() && json_object_get(j_scope_session, "password_authenticated") == json_false()) {
              json_object_set_new(j_scope_session, "authorized", json_false());
            } else if ((json_object_get(j_scope_session, "password_required") == json_true() && json_object_get(j_scope_session, "password_authenticated") == json_true()) || json_object_get(j_scope_session, "password_required") == json_false()) {
              json_object_foreach(json_object_get(j_scope_session, "schemes"), group, j_group) {
                group_allowed = 0;
                json_array_foreach(j_group, index, j_scheme) {
                  if (!group_allowed && json_object_get(j_scheme, "scheme_authenticated") == json_true()) {
                    if (!json_array_has_string(json_object_get(json_object_get(j_session, "session"), "amr"), json_string_value(json_object_get(j_scheme, "scheme_type")))) {
                      json_array_append(json_object_get(json_object_get(j_session, "session"), "amr"), json_object_get(j_scheme, "scheme_type"));
                    }
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
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_session_client_scope - Error glewlwyd_callback_get_client_granted_scopes");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_grant);
  } else if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_session_client_scope - Error glewlwyd_callback_check_session_valid");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_session);
  return j_return;
}

/**
 * Verify that the refresh token is still valid to get an access token
 */
static json_t * validate_refresh_token(struct _oidc_config * config, const char * refresh_token) {
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
      j_query = json_pack("{sss[ssssssssss]s{sssssis{ssss}}}",
                          "table",
                          GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                          "columns",
                            "gpor_id",
                            "gpoc_id",
                            "gpor_username AS username",
                            "gpor_client_id AS client_id",
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_issued_at) AS issued_at", "gpor_issued_at AS issued_at", "EXTRACT(EPOCH FROM gpor_issued_at)::integer AS issued_at"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_expires_at) AS expired_at", "gpor_expires_at AS expired_at", "EXTRACT(EPOCH FROM gpor_expires_at)::integer AS expired_at"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_last_seen) AS last_seen", "gpor_last_seen AS last_seen", "EXTRACT(EPOCH FROM gpor_last_seen)::integer AS last_seen"),
                            "gpor_duration AS duration",
                            "gpor_rolling_expiration",
                            "gpor_claims_request AS claims_request",
                          "where",
                            "gpor_plugin_name",
                            config->name,
                            "gpor_token_hash",
                            token_hash,
                            "gpor_enabled",
                            1,
                            "gpor_expires_at",
                              "operator",
                              "raw",
                              "value",
                              expires_at_clause);
      o_free(expires_at_clause);
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result) > 0) {
          json_object_set(json_array_get(j_result, 0), "rolling_expiration", json_integer_value(json_object_get(json_array_get(j_result, 0), "gpor_rolling_expiration"))?json_true():json_false());
          json_object_del(json_array_get(j_result, 0), "gpor_rolling_expiration");
          j_query = json_pack("{sss[s]s{sO}}",
                              "table",
                              GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN_SCOPE,
                              "columns",
                                "gpors_scope AS scope",
                              "where",
                                "gpor_id",
                                json_object_get(json_array_get(j_result, 0), "gpor_id"));
          res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result_scope, NULL);
          if (res == H_OK) {
            if (!json_object_set_new(json_array_get(j_result, 0), "scope", json_array())) {
              json_array_foreach(j_result_scope, index, j_element) {
                json_array_append(json_object_get(json_array_get(j_result, 0), "scope"), json_object_get(j_element, "scope"));
              }
              j_return = json_pack("{sisO}", "result", G_OK, "token", json_array_get(j_result, 0));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_refresh_token - Error json_object_set_new");
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            json_decref(j_result_scope);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_refresh_token - Error executing j_query (2)");
            j_return = json_pack("{si}", "result", G_ERROR_DB);
          }
          json_decref(j_query);
        } else {
          j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_refresh_token - Error executing j_query (1)");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_refresh_token - Error glewlwyd_callback_generate_hash");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    o_free(token_hash);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

/**
 * get a list of refresh token for a specified user
 */
static json_t * refresh_token_list_get(struct _oidc_config * config, const char * username, const char * pattern, size_t offset, size_t limit, const char * sort) {
  json_t * j_query, * j_result, * j_return, * j_element = NULL;
  int res;
  size_t index = 0, token_hash_dec_len = 0;
  char * pattern_escaped, * pattern_clause, * name_escaped = NULL;
  unsigned char token_hash_dec[128];
  
  j_query = json_pack("{sss[ssssssssss]s{ssss}sisiss}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                      "columns",
                        "gpor_token_hash",
                        "gpor_authorization_type",
                        "gpor_client_id AS client_id",
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_issued_at) AS issued_at", "gpor_issued_at AS issued_at", "EXTRACT(EPOCH FROM gpor_issued_at)::integer AS issued_at"),
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_expires_at) AS expires_at", "gpor_expires_at AS expires_at", "EXTRACT(EPOCH FROM gpor_expires_at)::integer AS expires_at"),
                        SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_last_seen) AS last_seen", "gpor_last_seen AS last_seen", "EXTRACT(EPOCH FROM gpor_last_seen)::integer AS last_seen"),
                        "gpor_rolling_expiration",
                        "gpor_issued_for AS issued_for",
                        "gpor_user_agent AS user_agent",
                        "gpor_enabled",
                      "where",
                        "gpor_plugin_name",
                        config->name,
                        "gpor_username",
                        username,
                      "offset",
                      offset,
                      "limit",
                      limit,
                      "order_by",
                      "gpor_last_seen DESC");
  if (sort != NULL) {
    json_object_set_new(j_query, "order_by", json_string(sort));
  }
  if (pattern != NULL) {
    name_escaped = h_escape_string_with_quotes(config->glewlwyd_config->glewlwyd_config->conn, config->name);
    pattern_escaped = h_escape_string_with_quotes(config->glewlwyd_config->glewlwyd_config->conn, pattern);
    pattern_clause = msprintf("IN (SELECT gpor_id FROM "GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN" WHERE (gpor_user_agent LIKE '%%'||%s||'%%' OR gpor_issued_for LIKE '%%'||%s||'%%') AND gpor_plugin_name=%s)", pattern_escaped, pattern_escaped, name_escaped);
    json_object_set_new(json_object_get(j_query, "where"), "gpor_id", json_pack("{ssss}", "operator", "raw", "value", pattern_clause));
    o_free(pattern_clause);
    o_free(pattern_escaped);
    o_free(name_escaped);
  }
  res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    json_array_foreach(j_result, index, j_element) {
      json_object_set(j_element, "rolling_expiration", (json_integer_value(json_object_get(j_element, "gpor_rolling_expiration"))?json_true():json_false()));
      json_object_set(j_element, "enabled", (json_integer_value(json_object_get(j_element, "gpor_enabled"))?json_true():json_false()));
      json_object_del(j_element, "gpor_rolling_expiration");
      json_object_del(j_element, "gpor_enabled");
      if (o_base64_2_base64url((unsigned char *)json_string_value(json_object_get(j_element, "gpor_token_hash")), json_string_length(json_object_get(j_element, "gpor_token_hash")), token_hash_dec, &token_hash_dec_len)) {
        json_object_set_new(j_element, "token_hash", json_stringn((char *)token_hash_dec, token_hash_dec_len));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_list_get - Error o_base64_2_base64url");
        json_object_set_new(j_element, "token_hash", json_string("error"));
      }
      json_object_del(j_element, "gpor_token_hash");
      switch(json_integer_value(json_object_get(j_element, "gpor_authorization_type"))) {
        case GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE:
          json_object_set_new(j_element, "authorization_type", json_string("code"));
          break;
        default:
          json_object_set_new(j_element, "authorization_type", json_string("unknown"));
          break;
      }
      json_object_del(j_element, "gpor_authorization_type");
    }
    j_return = json_pack("{sisO}", "result", G_OK, "refresh_token", j_result);
    json_decref(j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_list_get - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

/**
 * disable a refresh token based on its signature
 */
static int refresh_token_disable(struct _oidc_config * config, const char * username, const char * token_hash, const char * ip_source) {
  json_t * j_query, * j_result;
  int res, ret;
  unsigned char token_hash_dec[128];
  size_t token_hash_dec_len = 0;
  
  if (o_base64url_2_base64((unsigned char *)token_hash, o_strlen(token_hash), token_hash_dec, &token_hash_dec_len)) {
    j_query = json_pack("{sss[ss]s{ssssss%}}",
                        "table",
                        GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                        "columns",
                          "gpor_id",
                          "gpor_enabled",
                        "where",
                          "gpor_plugin_name",
                          config->name,
                          "gpor_username",
                          username,
                          "gpor_token_hash",
                          token_hash_dec,
                          token_hash_dec_len);
    res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gpor_enabled"))) {
          j_query = json_pack("{sss{si}s{ssssss%}}",
                              "table",
                              GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                              "set",
                                "gpor_enabled",
                                0,
                              "where",
                                "gpor_plugin_name",
                                config->name,
                                "gpor_username",
                                username,
                                "gpor_token_hash",
                                token_hash_dec,
                                token_hash_dec_len);
          res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
          json_decref(j_query);
          if (res == H_OK) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "refresh_token_disable - token '[...%s]' disabled, origin: %s", token_hash + (o_strlen(token_hash) - (o_strlen(token_hash)>=8?8:o_strlen(token_hash))), ip_source);
            ret = G_OK;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_disable - Error executing j_query (2)");
            ret = G_ERROR_DB;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "refresh_token_disable - Error token '[...%s]' already disabled, origin: %s", token_hash + (o_strlen(token_hash) - (o_strlen(token_hash)>=8?8:o_strlen(token_hash))), ip_source);
          ret = G_ERROR_PARAM;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "refresh_token_disable - Error token '[...%s]' not found, origin: %s", token_hash + (o_strlen(token_hash) - (o_strlen(token_hash)>=8?8:o_strlen(token_hash))), ip_source);
        ret = G_ERROR_NOT_FOUND;
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_disable - Error executing j_query (1)");
      ret = G_ERROR_DB;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "refresh_token_disable - Error o_base64url_2_base64");
    ret = G_ERROR_PARAM;
  }
  return ret;
}

/**
 * update settings for a refresh token
 */
static int update_refresh_token(struct _oidc_config * config, json_int_t gpor_id, json_int_t refresh_token_duration, int disable, time_t now) {
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
                      GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                      "set",
                        "gpor_last_seen",
                          "raw",
                          last_seen_clause,
                      "where",
                        "gpor_plugin_name",
                        config->name,
                        "gpor_id",
                        gpor_id);
  o_free(last_seen_clause);
  if (refresh_token_duration) {
    if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_MARIADB) {
      expires_at_clause = msprintf("FROM_UNIXTIME(%u)", (now + (unsigned int)refresh_token_duration));
    } else if (config->glewlwyd_config->glewlwyd_config->conn->type==HOEL_DB_TYPE_PGSQL) {
      expires_at_clause = msprintf("TO_TIMESTAMP(%u)", (now + (unsigned int)refresh_token_duration));
    } else { // HOEL_DB_TYPE_SQLITE
      expires_at_clause = msprintf("%u", (now + (unsigned int)refresh_token_duration));
    }
    json_object_set_new(json_object_get(j_query, "set"), "gpor_expires_at", json_pack("{ss}", "raw", expires_at_clause));
    o_free(expires_at_clause);
  }
  if (disable) {
    json_object_set_new(json_object_get(j_query, "set"), "gpor_enabled", json_integer(0));
  }
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc update_refresh_token - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

/**
 * Download a request object from an URI
 */
static char * get_request_from_uri(struct _oidc_config * config, const char * request_uri) {
  struct _u_request req;
  struct _u_response resp;
  char * str_request = NULL;

  ulfius_init_request(&req);
  ulfius_init_response(&resp);

  req.http_verb = o_strdup("GET");
  req.http_url = o_strdup(request_uri);
  if (json_object_get(config->j_params, "request-uri-allow-https-non-secure") == json_true()) {
    req.check_server_certificate = 0;
  }
  
  if (ulfius_send_http_request(&req, &resp) != U_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_request_from_uri - Error ulfius_send_http_request");
  } else if (resp.status == 200) {
    str_request = o_malloc(resp.binary_body_length + 1);
    if (str_request != NULL) {
      memcpy(str_request, resp.binary_body, resp.binary_body_length);
      str_request[resp.binary_body_length] = '\0';
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_request_from_uri - Error allocating resources for str_request");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_request_from_uri - Error ulfius_send_http_request response status is %d", resp.status);
  }
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  return str_request;
}

static json_t * verify_request_signature(struct _oidc_config * config, jwt_t * jwt, const char * client_id, const char * ip_source) {
  json_t * j_client, * j_return;
  jwks_t * jwks = NULL;
  jwk_t * jwk = NULL;
  jwa_alg alg = R_JWA_ALG_UNKNOWN;
  
  j_client = config->glewlwyd_config->glewlwyd_plugin_callback_get_client(config->glewlwyd_config, client_id);
  if (check_result_value(j_client, G_OK)) {
    // Client must have a non empty client_secret, a public key available, a jwks or be non confidential
    alg = r_jwt_get_sign_alg(jwt);
    if (json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
      if (alg == R_JWA_ALG_HS256 || alg == R_JWA_ALG_HS384 || alg == R_JWA_ALG_HS512) {
        if (json_string_length(json_object_get(json_object_get(j_client, "client"), "client_secret"))) {
          if (r_jwk_init(&jwk) == RHN_OK && r_jwk_import_from_symmetric_key(jwk, (const unsigned char *)json_string_value(json_object_get(json_object_get(j_client, "client"), "client_secret")), json_string_length(json_object_get(json_object_get(j_client, "client"), "client_secret"))) == RHN_OK && r_jwt_verify_signature(jwt, jwk, 0) == RHN_OK) {
            j_return = json_pack("{sisO}", "result", G_OK, "client", json_object_get(j_client, "client"));
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "verify_request_signature - jwt has an invalid signature (client_secret), origin: %s", ip_source);
            j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          }
          r_jwk_free(jwk);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "verify_request_signature - client has no attribute 'client_secret', origin: %s", ip_source);
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      } else if (alg == R_JWA_ALG_ES256 || alg == R_JWA_ALG_ES384 || alg == R_JWA_ALG_ES512 || alg == R_JWA_ALG_RS256 || alg == R_JWA_ALG_RS384 || alg == R_JWA_ALG_RS512 || alg == R_JWA_ALG_PS256 || alg == R_JWA_ALG_PS384 || alg == R_JWA_ALG_PS512 || alg == R_JWA_ALG_EDDSA) {
        if (json_string_length(json_object_get(json_object_get(j_client, "client"), json_string_value(json_object_get(config->j_params, "client-jwks_uri-parameter")))) && o_strlen(r_jwt_get_header_str_value(jwt, "kid"))) {
          if (r_jwks_init(&jwks) == RHN_OK && r_jwks_import_from_uri(jwks, json_string_value(json_object_get(json_object_get(j_client, "client"), json_string_value(json_object_get(config->j_params, "client-jwks_uri-parameter")))), config->x5u_flags) == RHN_OK) {
            if ((jwk = r_jwks_get_by_kid(jwks, r_jwt_get_header_str_value(jwt, "kid"))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "verify_request_signature - unable to get pubkey from jwks_uri, origin: %s", ip_source);
            }
          }
          r_jwks_free(jwks);
        } else if (json_is_object(json_object_get(json_object_get(j_client, "client"), json_string_value(json_object_get(config->j_params, "client-jwks-parameter")))) && o_strlen(r_jwt_get_header_str_value(jwt, "kid"))) {
          if (r_jwks_init(&jwks) == RHN_OK && r_jwks_import_from_json_t(jwks, json_object_get(json_object_get(j_client, "client"), json_string_value(json_object_get(config->j_params, "client-jwks-parameter")))) == RHN_OK) {
            if ((jwk = r_jwks_get_by_kid(jwks, r_jwt_get_header_str_value(jwt, "kid"))) == NULL) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "verify_request_signature - unable to get pubkey from jwks, origin: %s", ip_source);
            }
          }
          r_jwks_free(jwks);
        } else if (json_string_length(json_object_get(json_object_get(j_client, "client"), json_string_value(json_object_get(config->j_params, "client-pubkey-parameter"))))) {
          if (r_jwk_init(&jwk) != RHN_OK || r_jwk_import_from_pem_der(jwk, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (const unsigned char *)json_string_value(json_object_get(json_object_get(j_client, "client"), json_string_value(json_object_get(config->j_params, "client-pubkey-parameter")))), json_string_length(json_object_get(json_object_get(j_client, "client"), json_string_value(json_object_get(config->j_params, "client-pubkey-parameter"))))) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "verify_request_signature - unable to get pubkey from client, origin: %s", ip_source);
            r_jwk_free(jwk);
            jwk = NULL;
          }
        }
        if (jwk != NULL) {
          if (r_jwt_verify_signature(jwt, jwk, 0) == RHN_OK) {
            j_return = json_pack("{sisO}", "result", G_OK, "client", json_object_get(j_client, "client"));
          } else {
            y_log_message(Y_LOG_LEVEL_DEBUG, "verify_request_signature - jwt has an invalid signature (pubkey)", ip_source);
            j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          }
          r_jwk_free(jwk);
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "verify_request_signature - invalid pubkey, origin: %s", ip_source);
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "verify_request_signature - jwt has unsupported algorithm: %s, origin: %s", r_jwa_alg_to_str(alg), ip_source);
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
    } else {
      // jwt_header must have alg set to "none"
      if (alg == R_JWA_ALG_NONE) {
        j_return = json_pack("{sisO}", "result", G_OK, "client", json_object_get(j_client, "client"));
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "verify_request_signature - jwt alg is not none although the client is not confidential, origin: %s", ip_source);
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
    }
  } else if (check_result_value(j_client, G_ERROR_NOT_FOUND) || check_result_value(j_client, G_ERROR_PARAM)) {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "verify_request_signature - Error getting header or payload, origin: %s", ip_source);
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_client);
  
  return j_return;
}

static int decrypt_request_token(struct _oidc_config * config, jwt_t * jwt) {
  int ret, res;
  jwk_t * jwk = NULL;
  unsigned char * key = NULL, key_hash[64] = {0};
  size_t key_len = 0, key_hash_len = 64;
  jwa_alg alg;
  jwa_enc enc;
  unsigned int bits = 0;
  
  if (r_jwt_get_type(jwt) == R_JWT_TYPE_SIGN) {
    // Not encrypted
    ret = G_OK;
  } else if (r_jwt_get_type(jwt) == R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT) {
    if (json_object_get(config->j_params, "request-parameter-allow-encrypted") == json_true()) {
      alg = r_jwt_get_enc_alg(jwt);
      enc = r_jwt_get_enc(jwt);
      if (r_jwks_size(config->jwt_sign->jwks_privkey_sign) == 1) {
        jwk = r_jwk_copy(config->jwk_sign_default);
      } else if (r_jwt_get_header_str_value(jwt, "kid") != NULL) {
        jwk = r_jwks_get_by_kid(config->jwt_sign->jwks_privkey_sign, r_jwt_get_header_str_value(jwt, "kid"));
      } else if (json_string_length(json_object_get(config->j_params, "default-kid"))) {
        jwk = r_jwks_get_by_kid(config->jwt_sign->jwks_privkey_sign, json_string_value(json_object_get(config->j_params, "default-kid")));
      }
      if (jwk != NULL) {
        if (r_jwk_key_type(jwk, &bits, 0) & R_KEY_TYPE_SYMMETRIC) {
          if (alg == R_JWA_ALG_A128GCMKW || alg == R_JWA_ALG_A128KW || alg == R_JWA_ALG_A192GCMKW || alg == R_JWA_ALG_A192KW || alg == R_JWA_ALG_A256GCMKW || alg == R_JWA_ALG_A256KW || alg == R_JWA_ALG_DIR) {
            key_len = (size_t)bits;
            if (key_len && (key = o_malloc(key_len)) != NULL) {
              if (r_jwk_export_to_symmetric_key(jwk, key, &key_len) == RHN_OK) {
                if (generate_digest_raw((alg == R_JWA_ALG_DIR?digest_SHA512:digest_SHA256), key, key_len, key_hash, &key_hash_len)) {
                  if (alg == R_JWA_ALG_DIR) {
                    key_hash_len = get_enc_key_size(enc);
                  } else if (alg == R_JWA_ALG_A128GCMKW || alg == R_JWA_ALG_A128KW) {
                    key_hash_len = 16;
                  } else if (alg == R_JWA_ALG_A192GCMKW || alg == R_JWA_ALG_A192KW) {
                    key_hash_len = 24;
                  }
                  r_jwk_free(jwk);
                  jwk = NULL;
                  if (r_jwk_init(&jwk) != RHN_OK || r_jwk_import_from_symmetric_key(jwk, key_hash, key_hash_len) != RHN_OK) {
                    y_log_message(Y_LOG_LEVEL_ERROR, "decrypt_request_token - Error setting jwk");
                    r_jwk_free(jwk);
                    jwk = NULL;
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "decrypt_request_token - Error generate_digest_raw");
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "decrypt_request_token - Error r_jwk_export_to_symmetric_key");
              }
              o_free(key);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "decrypt_request_token - Error allocating resources for key");
            }
          } else {
            // Key type differs
            r_jwk_free(jwk);
            jwk = NULL;
          }
        } else {
          if (alg == R_JWA_ALG_A128GCMKW || alg == R_JWA_ALG_A128KW || alg == R_JWA_ALG_A192GCMKW || alg == R_JWA_ALG_A192KW || alg == R_JWA_ALG_A256GCMKW || alg == R_JWA_ALG_A256KW || alg == R_JWA_ALG_DIR) {
            // Key type differs
            r_jwk_free(jwk);
            jwk = NULL;
          }
        }
      }
      if (jwk != NULL) {
        if ((res = r_jwt_decrypt_nested(jwt, jwk, 0)) == RHN_OK) {
          ret = G_OK;
        } else if (res == RHN_ERROR_INVALID) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "decrypt_request_token - invalid decrypt key");
          ret = G_ERROR_PARAM;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "decrypt_request_token - Error r_jwt_decrypt_nested");
          ret = G_ERROR;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "decrypt_request_token - No key to decrypt");
        ret = G_ERROR;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "decrypt_request_token - Encrypted requests not allowed");
      ret = G_ERROR_PARAM;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "decrypt_request_token - invalid nested JWT type");
    ret = G_ERROR_PARAM;
  }
  r_jwk_free(jwk);
  return ret;
}

/**
 * validate a request object in jwt format
 */
static json_t * validate_jwt_auth_request(struct _oidc_config * config, const char * jwt_request, const char * ip_source) {
  json_t * j_return, * j_result;
  jwt_t * jwt = NULL;
  
  if (jwt_request != NULL) {
    if (r_jwt_init(&jwt) == RHN_OK && r_jwt_parse(jwt, jwt_request, 0) == RHN_OK && decrypt_request_token(config, jwt) == G_OK) {
      // request or request_uri must not be present in the payload
      if (r_jwt_get_claim_str_value(jwt, "request") == NULL && r_jwt_get_claim_str_value(jwt, "	request_uri") == NULL) {
        j_result = verify_request_signature(config, jwt, r_jwt_get_claim_str_value(jwt, "client_id"), ip_source);
        if (check_result_value(j_result, G_OK)) {
          j_return = json_pack("{sisosO}", "result", G_OK, "request", r_jwt_get_full_claims_json_t(jwt), "client", json_object_get(j_result, "client"));
        } else if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "validate_jwt_auth_request - Error verify_request_signature");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "validate_jwt_auth_request - jwt has an invalid payload with attribute request or request_uri, origin: %s", ip_source);
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "validate_jwt_auth_request - Error jwt_request is not a valid jwt, origin: %s", ip_source);
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    }
    r_jwt_free(jwt);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "validate_jwt_auth_request - Error jwt_request is NULL");
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  
  return j_return;
}

static int check_request_jti_unused(struct _oidc_config * config, const char * jti, const char * iss, const char * ip_source) {
  json_t * j_query, * j_result = NULL;
  int ret, res;
  char * jti_hash = NULL;
  
  if (o_strlen(jti)) {
    jti_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, jti);
    j_query = json_pack("{sss[s]s{ssssss}}",
                        "table",
                        GLEWLWYD_PLUGIN_OIDC_TABLE_CLIENT_TOKEN_REQUEST,
                        "columns",
                          "gpoctr_id",
                        "where",
                          "gpoctr_plugin_name",
                          config->name,
                          "gpoctr_cient_id",
                          iss,
                          "gpoctr_jti_hash",
                          jti_hash);
    res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "check_request_jti_unused - jti already used for client '%s', origin %s", iss, ip_source);
        ret = G_ERROR_UNAUTHORIZED;
      } else {
        j_query = json_pack("{sss{ssssssss}}",
                            "table",
                            GLEWLWYD_PLUGIN_OIDC_TABLE_CLIENT_TOKEN_REQUEST,
                            "values",
                              "gpoctr_plugin_name",
                              config->name,
                              "gpoctr_cient_id",
                              iss,
                              "gpoctr_issued_for",
                              ip_source,
                              "gpoctr_jti_hash",
                              jti_hash);
        res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
        json_decref(j_query);
        if (res == H_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "check_request_jti_unused - Error excuting j_query (2)");
          ret = G_ERROR_DB;
        }
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "check_request_jti_unused - Error excuting j_query (1)");
      ret = G_ERROR_DB;
    }
    o_free(jti_hash);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "check_request_jti_unused - no jti in jwt request for client '%s', origin %s", iss, ip_source);
    ret = G_ERROR_PARAM;
  }
  return ret;
}

/**
 * validate a assertion object in jwt format
 */
static json_t * validate_jwt_assertion_request(struct _oidc_config * config, const char * jwt_assertion, const char * ip_source) {
  json_t * j_return, * j_result;
  jwt_t * jwt = NULL;
  char * token_endpoint, * plugin_url = config->glewlwyd_config->glewlwyd_callback_get_plugin_external_url(config->glewlwyd_config, config->name);
  json_int_t j_now = (json_int_t)time(NULL);
  
  token_endpoint = msprintf("%s/token", plugin_url);
  
  if (jwt_assertion != NULL) {
    if (r_jwt_init(&jwt) == RHN_OK && r_jwt_parse(jwt, jwt_assertion, 0) == RHN_OK && decrypt_request_token(config, jwt) == G_OK) {
      // Extract header and payload
      j_result = verify_request_signature(config, jwt, r_jwt_get_claim_str_value(jwt, "iss"), ip_source);
      if (check_result_value(j_result, G_OK)) {
        if (0 == o_strcmp(r_jwt_get_claim_str_value(jwt, "iss"), r_jwt_get_claim_str_value(jwt, "sub")) && r_jwt_get_claim_int_value(jwt, "exp") > 0 && r_jwt_get_claim_int_value(jwt, "exp") > j_now && ((r_jwt_get_claim_int_value(jwt, "exp") - j_now) <= config->auth_token_max_age) && 0 == o_strcmp(token_endpoint, r_jwt_get_claim_str_value(jwt, "aud")) && check_request_jti_unused(config, r_jwt_get_claim_str_value(jwt, "jti"), r_jwt_get_claim_str_value(jwt, "iss"), ip_source) == G_OK) {
          j_return = json_pack("{sisosO}", "result", G_OK, "request", r_jwt_get_full_claims_json_t(jwt), "client", json_object_get(j_result, "client"));
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "invalid jwt assertion content");
          y_log_message(Y_LOG_LEVEL_DEBUG, " - iss: '%s'", r_jwt_get_claim_str_value(jwt, "iss"));
          y_log_message(Y_LOG_LEVEL_DEBUG, " - sub: '%s'", r_jwt_get_claim_str_value(jwt, "sub"));
          y_log_message(Y_LOG_LEVEL_DEBUG, " - exp: %"JSON_INTEGER_FORMAT, r_jwt_get_claim_int_value(jwt, "exp"));
          y_log_message(Y_LOG_LEVEL_DEBUG, " - aud: '%s'", r_jwt_get_claim_str_value(jwt, "aud"));
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        }
      } else if (check_result_value(j_result, G_ERROR_UNAUTHORIZED)) {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "validate_jwt_assertion_request - Error verify_request_signature");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "validate_jwt_assertion_request - Error jwt_assertion is not a valid jwt, origin: %s", ip_source);
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    }
    r_jwt_free(jwt);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "validate_jwt_assertion_request - Error jwt_assertion is NULL");
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  o_free(token_endpoint);
  o_free(plugin_url);
  
  return j_return;
}

/**
 * return a state parameter
 */
static char * get_state_param(const char * state_value) {
  char * state_encoded, * state_param;
  
  if (state_value == NULL) {
    state_param = o_strdup("");
  } else {
    state_encoded = url_encode(state_value);
    state_param = msprintf("&state=%s", state_encoded);
    o_free(state_encoded);
  }
  return state_param;
}

static int revoke_refresh_token(struct _oidc_config * config, const char * token) {
  json_t * j_query;
  int res, ret;
  char * token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token);
  
  j_query = json_pack("{sss{si}s{ssss}}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                      "set",
                        "gpor_enabled",
                        0,
                      "where",
                        "gpor_plugin_name",
                        config->name,
                        "gpor_token_hash",
                        token_hash);
  o_free(token_hash);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "revoke_refresh_token - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static int revoke_access_token(struct _oidc_config * config, const char * token) {
  json_t * j_query;
  int res, ret;
  char * token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token);
  
  j_query = json_pack("{sss{si}s{ssss}}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN,
                      "set",
                        "gpoa_enabled",
                        0,
                      "where",
                        "gpoa_plugin_name",
                        config->name,
                        "gpoa_token_hash",
                        token_hash);
  o_free(token_hash);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "revoke_access_token - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static int revoke_id_token(struct _oidc_config * config, const char * token) {
  json_t * j_query;
  int res, ret;
  char * token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, token);
  
  j_query = json_pack("{sss{si}s{ssss}}",
                      "table",
                      GLEWLWYD_PLUGIN_OIDC_TABLE_ID_TOKEN,
                      "set",
                        "gpoi_enabled",
                        0,
                      "where",
                        "gpoi_plugin_name",
                        config->name,
                        "gpoi_hash",
                        token_hash);
  o_free(token_hash);
  res = h_update(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    ret = G_OK;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "revoke_id_token - Error executing j_query");
    ret = G_ERROR_DB;
  }
  return ret;
}

static json_t * get_token_metadata(struct _oidc_config * config, const char * token, const char * token_type_hint, const char * client_id) {
  json_t * j_query, * j_result, * j_result_scope, * j_return = NULL, * j_element = NULL, * j_client = NULL;
  int res, found_refresh = 0, found_access = 0, found_id_token = 0;
  size_t index = 0;
  char * token_hash = NULL, * scope_list = NULL, * expires_at_clause, * sub = NULL;
  time_t now;
  
  if (o_strlen(token)) {
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
      j_query = json_pack("{sss[ssssssss]s{sssss{ssss}}}",
                          "table",
                          GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN,
                          "columns",
                            "gpor_id",
                            "gpor_username AS username",
                            "gpor_client_id AS client_id",
                            "gpor_client_id AS aud",
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_issued_at) AS iat", "gpor_issued_at AS iat", "EXTRACT(EPOCH FROM gpor_issued_at)::integer AS iat"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_issued_at) AS nbf", "gpor_issued_at AS nbf", "EXTRACT(EPOCH FROM gpor_issued_at)::integer AS nbf"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpor_expires_at) AS exp", "gpor_expires_at AS exp", "EXTRACT(EPOCH FROM gpor_expires_at)::integer AS exp"),
                            "gpor_enabled",
                          "where",
                            "gpor_plugin_name",
                            config->name,
                            "gpor_token_hash",
                            token_hash,
                            "gpor_expires_at",
                              "operator",
                              "raw",
                              "value",
                              expires_at_clause);
      if (client_id != NULL) {
        json_object_set_new(json_object_get(j_query, "where"), "gpor_client_id", json_string(client_id));
      }
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          found_refresh = 1;
          if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gpor_enabled"))) {
            json_object_set_new(json_array_get(j_result, 0), "active", json_true());
            json_object_set_new(json_array_get(j_result, 0), "token_type", json_string("refresh_token"));
            json_object_del(json_array_get(j_result, 0), "gpor_enabled");
            if (json_object_get(json_array_get(j_result, 0), "client_id") == json_null()) {
              json_object_del(json_array_get(j_result, 0), "client_id");
              json_object_del(json_array_get(j_result, 0), "aud");
              sub = get_sub(config, json_string_value(json_object_get(json_array_get(j_result, 0), "username")), NULL);
            } else {
              j_client = config->glewlwyd_config->glewlwyd_plugin_callback_get_client(config->glewlwyd_config, json_string_value(json_object_get(json_array_get(j_result, 0), "client_id")));
              if (check_result_value(j_client, G_OK)) {
                sub = get_sub(config, json_string_value(json_object_get(json_array_get(j_result, 0), "username")), json_object_get(j_client, "client"));
              }
              json_decref(j_client);
            }
            if (sub != NULL) {
              json_object_set_new(json_array_get(j_result, 0), "sub", json_string(sub));
              o_free(sub);
            }
            if (json_object_get(json_array_get(j_result, 0), "username") == json_null()) {
              json_object_del(json_array_get(j_result, 0), "username");
            }
            j_query = json_pack("{sss[s]s{sO}}",
                                "table",
                                GLEWLWYD_PLUGIN_OIDC_TABLE_REFRESH_TOKEN_SCOPE,
                                "columns",
                                  "gpors_scope AS scope",
                                "where",
                                  "gpor_id",
                                  json_object_get(json_array_get(j_result, 0), "gpor_id"));
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
              json_object_del(json_array_get(j_result, 0), "gpor_id");
              j_return = json_pack("{sisO}", "result", G_OK, "token", json_array_get(j_result, 0));
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_refresh_token - Error executing j_query scope refresh_token");
              j_return = json_pack("{si}", "result", G_ERROR_DB);
            }
          } else {
            j_return = json_pack("{sis{so}}", "result", G_OK, "token", "active", json_false());
          }
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_token_metadata - Error executing j_query refresh_token");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    }
    if ((token_type_hint == NULL && !found_refresh) || 0 == o_strcmp("access_token", token_type_hint)) {
      j_query = json_pack("{sss[ssssssss]s{ssss}}",
                          "table",
                          GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN,
                          "columns",
                            "gpoa_id",
                            "gpoa_username AS username",
                            "gpoa_client_id AS client_id",
                            "gpoa_client_id AS aud",
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpoa_issued_at) AS iat", "gpoa_issued_at AS iat", "EXTRACT(EPOCH FROM gpoa_issued_at)::integer AS iat"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpoa_issued_at) AS nbf", "gpoa_issued_at AS nbf", "EXTRACT(EPOCH FROM gpoa_issued_at)::integer AS nbf"),
                            "gpoa_jti as jti",
                            "gpoa_enabled",
                          "where",
                            "gpoa_plugin_name",
                            config->name,
                            "gpoa_token_hash",
                            token_hash);
      if (client_id != NULL) {
        json_object_set_new(json_object_get(j_query, "where"), "gpoa_client_id", json_string(client_id));
      }
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          found_access = 1;
          if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gpoa_enabled")) && json_integer_value(json_object_get(json_array_get(j_result, 0), "iat")) + json_integer_value(json_object_get(config->j_params, "access-token-duration")) > now) {
            json_object_set_new(json_array_get(j_result, 0), "sub", json_string(sub));
            json_object_set_new(json_array_get(j_result, 0), "active", json_true());
            json_object_set_new(json_array_get(j_result, 0), "token_type", json_string("access_token"));
            json_object_set_new(json_array_get(j_result, 0), "exp", json_integer(json_integer_value(json_object_get(json_array_get(j_result, 0), "iat")) + json_integer_value(json_object_get(config->j_params, "access-token-duration"))));
            json_object_del(json_array_get(j_result, 0), "gpoa_enabled");
            if (json_object_get(json_array_get(j_result, 0), "client_id") == json_null()) {
              json_object_del(json_array_get(j_result, 0), "client_id");
              json_object_del(json_array_get(j_result, 0), "aud");
              sub = get_sub(config, json_string_value(json_object_get(json_array_get(j_result, 0), "username")), NULL);
            } else if (json_object_get(json_array_get(j_result, 0), "username") != json_null()) {
              j_client = config->glewlwyd_config->glewlwyd_plugin_callback_get_client(config->glewlwyd_config, json_string_value(json_object_get(json_array_get(j_result, 0), "client_id")));
              if (check_result_value(j_client, G_OK)) {
                sub = get_sub(config, json_string_value(json_object_get(json_array_get(j_result, 0), "username")), json_object_get(j_client, "client"));
              }
            }
            if (sub != NULL) {
              json_object_set_new(json_array_get(j_result, 0), "sub", json_string(sub));
              o_free(sub);
            }
            if (json_object_get(json_array_get(j_result, 0), "username") == json_null()) {
              json_object_del(json_array_get(j_result, 0), "username");
            }
            j_query = json_pack("{sss[s]s{sO}}",
                                "table",
                                GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN_SCOPE,
                                "columns",
                                  "gpoas_scope AS scope",
                                "where",
                                  "gpoa_id",
                                  json_object_get(json_array_get(j_result, 0), "gpoa_id"));
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
              json_object_del(json_array_get(j_result, 0), "gpoa_id");
              j_return = json_pack("{sisO}", "result", G_OK, "token", json_array_get(j_result, 0));
              if (j_client != NULL) {
                json_object_set(j_return, "client", json_object_get(j_client, "client"));
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_refresh_token - Error executing j_query scope access_token");
              j_return = json_pack("{si}", "result", G_ERROR_DB);
            }
            json_decref(j_client);
          } else {
            j_return = json_pack("{sis{so}}", "result", G_OK, "token", "active", json_false());
          }
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_token_metadata - Error executing j_query access_token");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    }
    if ((token_type_hint == NULL && !found_refresh && !found_access) || 0 == o_strcmp("id_token", token_type_hint)) {
      j_query = json_pack("{sss[sssssss]s{ssss}}",
                          "table",
                          GLEWLWYD_PLUGIN_OIDC_TABLE_ID_TOKEN,
                          "columns",
                            "gpoi_id",
                            "gpoi_username AS username",
                            "gpoi_client_id AS client_id",
                            "gpoi_client_id AS aud",
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpoi_issued_at) AS iat", "gpoi_issued_at AS iat", "EXTRACT(EPOCH FROM gpoi_issued_at)::integer AS iat"),
                            SWITCH_DB_TYPE(config->glewlwyd_config->glewlwyd_config->conn->type, "UNIX_TIMESTAMP(gpoi_issued_at) AS nbf", "gpoi_issued_at AS nbf", "EXTRACT(EPOCH FROM gpoi_issued_at)::integer AS nbf"),
                            "gpoi_enabled",
                          "where",
                            "gpoi_plugin_name",
                            config->name,
                            "gpoi_hash",
                            token_hash);
      if (client_id != NULL) {
        json_object_set_new(json_object_get(j_query, "where"), "gpoi_client_id", json_string(client_id));
      }
      res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
      json_decref(j_query);
      if (res == H_OK) {
        if (json_array_size(j_result)) {
          found_id_token = 1;
          if (json_integer_value(json_object_get(json_array_get(j_result, 0), "gpoi_enabled")) && json_integer_value(json_object_get(json_array_get(j_result, 0), "iat")) + json_integer_value(json_object_get(config->j_params, "access-token-duration")) > now) {
            json_object_set_new(json_array_get(j_result, 0), "sub", json_string(sub));
            json_object_set_new(json_array_get(j_result, 0), "active", json_true());
            json_object_set_new(json_array_get(j_result, 0), "token_type", json_string("id_token"));
            json_object_set_new(json_array_get(j_result, 0), "exp", json_integer(json_integer_value(json_object_get(json_array_get(j_result, 0), "iat")) + json_integer_value(json_object_get(config->j_params, "access-token-duration"))));
            json_object_del(json_array_get(j_result, 0), "gpoi_enabled");
            if (json_object_get(json_array_get(j_result, 0), "client_id") == json_null()) {
              json_object_del(json_array_get(j_result, 0), "client_id");
              json_object_del(json_array_get(j_result, 0), "aud");
              sub = get_sub(config, json_string_value(json_object_get(json_array_get(j_result, 0), "username")), NULL);
            } else {
              j_client = config->glewlwyd_config->glewlwyd_plugin_callback_get_client(config->glewlwyd_config, json_string_value(json_object_get(json_array_get(j_result, 0), "client_id")));
              if (check_result_value(j_client, G_OK)) {
                sub = get_sub(config, json_string_value(json_object_get(json_array_get(j_result, 0), "username")), json_object_get(j_client, "client"));
              }
              json_decref(j_client);
            }
            if (sub != NULL) {
              json_object_set_new(json_array_get(j_result, 0), "sub", json_string(sub));
              o_free(sub);
            }
            if (json_object_get(json_array_get(j_result, 0), "username") == json_null()) {
              json_object_del(json_array_get(j_result, 0), "username");
            }
            j_return = json_pack("{sisO}", "result", G_OK, "token", json_array_get(j_result, 0));
          } else {
            j_return = json_pack("{sis{so}}", "result", G_OK, "token", "active", json_false());
          }
        }
        json_decref(j_result);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_token_metadata - Error executing j_query id_token");
        j_return = json_pack("{si}", "result", G_ERROR_DB);
      }
    }
    if (!found_refresh && !found_access && !found_id_token && j_return == NULL) {
      j_return = json_pack("{sis{so}}", "result", G_OK, "token", "active", json_false());
    }
    o_free(token_hash);
    o_free(expires_at_clause);
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_PARAM);
  }
  return j_return;
}

static const char * get_client_id_for_introspection(struct _oidc_config * config, const struct _u_request * request) {
  if (u_map_get_case(request->map_header, "Authorization") != NULL && config->introspect_revoke_resource_config->oauth_scope != NULL) {
    return NULL;
  } else if (json_object_get(config->j_params, "introspection-revocation-allow-target-client") == json_true()) {
    return request->auth_basic_user;
  } else {
    return NULL;
  }
}

static int serialize_client_register(struct _oidc_config * config, const struct _u_request * request, json_t * j_client) {
  json_t * j_query, * j_result;
  int res, ret = G_OK;
  char * issued_for = get_client_hostname(request), * access_token_hash = NULL;
  json_int_t gpoa_id = 0;
  
  if (json_array_size(json_object_get(config->j_params, "register-client-auth-scope"))) {
    access_token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, (u_map_get_case(request->map_header, "Authorization") + o_strlen(HEADER_PREFIX_BEARER)));
    j_query = json_pack("{sss[s]s{ssss}}",
                        "table",
                        GLEWLWYD_PLUGIN_OIDC_TABLE_ACCESS_TOKEN,
                        "columns",
                          "gpoa_id",
                        "where",
                          "gpoa_plugin_name",
                          config->name,
                          "gpoa_token_hash",
                          access_token_hash);
    res = h_select(config->glewlwyd_config->glewlwyd_config->conn, j_query, &j_result, NULL);
    json_decref(j_query);
    if (res == H_OK) {
      if (json_array_size(j_result)) {
        gpoa_id = json_integer_value(json_object_get(json_array_get(j_result, 0), "gpoa_id"));
      } else {
        ret = G_ERROR_PARAM;
      }
      json_decref(j_result);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "serialize_client_register - Error executing j_query (1)");
      ret = G_ERROR_DB;
    }
  }
  if (ret == G_OK) {
    j_query = json_pack("{sss{sssOssss*}}",
                        "table",
                        GLEWLWYD_PLUGIN_OIDC_TABLE_CLIENT_REGISTRATION,
                        "values",
                          "gpocr_plugin_name",
                          config->name,
                          "gpocr_cient_id",
                          json_object_get(j_client, "client_id"),
                          "gpocr_issued_for",
                          issued_for,
                          "gpocr_user_agent",
                          u_map_get_case(request->map_header, "user-agent"));
    if (gpoa_id) {
      json_object_set_new(json_object_get(j_query, "values"), "gpoa_id", json_integer(gpoa_id));
    }
    res = h_insert(config->glewlwyd_config->glewlwyd_config->conn, j_query, NULL);
    json_decref(j_query);
    if (res != H_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "serialize_client_register - Error executing j_query (2)");
      ret = G_ERROR_DB;
    }
  }
  o_free(issued_for);
  o_free(access_token_hash);
  return ret;
}

static json_t * client_register(struct _oidc_config * config, const struct _u_request * request, json_t * j_registration) {
  json_t * j_client, * j_return = NULL;
  char client_id[GLEWLWYD_CLIENT_ID_LENGTH+1] = {}, client_secret[GLEWLWYD_CLIENT_SECRET_LENGTH+1] = {};
  
  j_client = json_object();
  rand_string_from_charset(client_id, GLEWLWYD_CLIENT_ID_LENGTH, "abcdefghijklmnopqrstuvwxyz0123456789");
  if (o_strlen(client_id)) {
    json_object_set(j_client, "enabled", json_true());
    json_object_set_new(j_client, "client_id", json_string(client_id));
    json_object_set_new(j_registration, "client_id", json_string(client_id));
    json_object_set(j_client, "name", json_object_get(j_registration, "client_name"));
    json_object_set(j_client, "redirect_uri", json_object_get(j_registration, "redirect_uris"));
    if (json_object_get(j_registration, "application_type") != NULL) {
      json_object_set(j_client, "application_type", json_object_get(j_registration, "application_type"));
    } else {
      json_object_set_new(j_client, "application_type", json_string("web"));
    }
    json_object_set(j_client, "contacts", json_object_get(j_registration, "contacts"));
    json_object_set(j_client, "logo_uri", json_object_get(j_registration, "logo_uri"));
    json_object_set(j_client, "client_uri", json_object_get(j_registration, "client_uri"));
    json_object_set(j_client, "policy_uri", json_object_get(j_registration, "policy_uri"));
    json_object_set(j_client, "tos_uri", json_object_get(j_registration, "tos_uri"));
    json_object_set(j_client, "pubkey", json_object_get(j_registration, "pubkey"));
    json_object_set(j_client, "jwks_uri", json_object_get(j_registration, "jwks_uri"));
    json_object_set(j_client, "jwks", json_object_get(j_registration, "jwks"));
    if (json_object_get(j_registration, "confidential") != json_false() && !json_string_length(json_object_get(j_registration, "pubkey")) && !json_string_length(json_object_get(j_registration, "jwks_uri")) && !json_string_length(json_object_get(j_registration, "jwks"))) {
      json_object_set(j_client, "confidential", json_true());
      rand_string(client_secret, GLEWLWYD_CLIENT_SECRET_LENGTH);
      if (!o_strlen(client_secret)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_register - Error generating client_secret");
        j_return = json_pack("{si}", "result", G_ERROR);
      } else {
        json_object_set_new(j_client, "client_secret", json_string(client_secret));
        json_object_set_new(j_registration, "client_secret", json_string(client_secret));
      }
    } else {
      json_object_set(j_client, "confidential", json_false());
    }
    if (!json_array_size(json_object_get(j_registration, "response_types"))) {
      json_object_set_new(j_client, "authorization_type", json_pack("[ss]", "code", "refresh_token"));
    } else {
      json_object_set(j_client, "authorization_type", json_object_get(j_registration, "response_types"));
    }
    if (json_object_get(config->j_params, "register-client-credentials-scope") != NULL) {
      json_object_set(j_client, "scope", json_object_get(config->j_params, "register-client-credentials-scope"));
    } else {
      json_object_set_new(j_client, "scope", json_array());
    }
    json_object_set_new(j_registration, "client_id_issued_at", json_integer(time(NULL)));
    json_object_set_new(j_registration, "client_secret_expires_at", json_integer(0));
    if (j_return == NULL) {
      if (serialize_client_register(config, request, j_client) == G_OK) {
        if ((config->glewlwyd_config->glewlwyd_plugin_callback_add_client(config->glewlwyd_config, j_client)) == G_OK) {
          j_return = json_pack("{sisO}", "result", G_OK, "client", j_registration);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "client_register - Error glewlwyd_plugin_callback_add_client");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "client_register - Error serialize_client_register");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "client_register - Error generating client_id");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_client);
  return j_return;
}

static json_t * is_client_registration_valid(struct _oidc_config * config, json_t * j_registration) {
  json_t * j_error = json_array(), * j_return, * j_element = NULL;
  size_t index = 0;
  jwks_t * jwks = NULL;

  if (j_error != NULL) {
    if (json_is_object(j_registration)) {
      if (!json_array_size(json_object_get(j_registration, "redirect_uris"))) {
        json_array_append_new(j_error, json_string("redirect_uris is mandatory and must be an array of strings"));
      } else {
        json_array_foreach(json_object_get(j_registration, "redirect_uris"), index, j_element) {
          if (0 != o_strncmp("https://", json_string_value(j_element), o_strlen("https://")) && 0 != o_strncmp("http://localhost", json_string_value(j_element), o_strlen("http://localhost"))) {
            json_array_append_new(j_error, json_string("a redirect_uri must be a 'https://' uri or a 'http://localhost' uri"));
          }
        }
      }
      if (json_object_get(j_registration, "response_types") != NULL && !json_is_array(json_object_get(j_registration, "response_types"))) {
        json_array_append_new(j_error, json_string("response_types is optional and must be an array of strings"));
      } else {
        json_array_foreach(json_object_get(j_registration, "response_types"), index, j_element) {
          if (0 != o_strcmp("code", json_string_value(j_element)) && 0 != o_strcmp("token", json_string_value(j_element)) && 0 != o_strcmp("id_token", json_string_value(j_element)) && 0 != o_strcmp("password", json_string_value(j_element)) && 0 != o_strcmp("client_credentials", json_string_value(j_element)) && 0 != o_strcmp("refresh_token", json_string_value(j_element)) && 0 != o_strcmp("delete_token", json_string_value(j_element))) {
            json_array_append_new(j_error, json_string("response_types must have one of the following values: 'code', 'token', 'id_token', 'password', 'client_credentials', 'refresh_token' or 'delete_token'"));
          }
        }
      }
      if (json_object_get(j_registration, "application_type") != NULL && 0 != o_strcmp("web", json_string_value(json_object_get(j_registration, "application_type"))) && 0 != o_strcmp("native", json_string_value(json_object_get(j_registration, "application_type")))) {
        json_array_append_new(j_error, json_string("application_type is optional and must have one of the following values: 'web', 'native'"));
      }
      if (json_object_get(j_registration, "contacts") != NULL && !json_is_array(json_object_get(j_registration, "contacts"))) {
        json_array_append_new(j_error, json_string("contacts is optional and must be an array of strings"));
      } else {
        json_array_foreach(json_object_get(j_registration, "contacts"), index, j_element) {
          if (!json_string_length(j_element)) {
            json_array_append_new(j_error, json_string("contact value must be a non empty string"));
          }
        }
      }
      if (json_object_get(j_registration, "client_confidential") != NULL && !json_is_boolean(json_object_get(j_registration, "client_confidential"))) {
        json_array_append_new(j_error, json_string("client_confidential is optional and must be a boolean"));
      }
      if (json_object_get(j_registration, "client_name") != NULL && !json_is_string(json_object_get(j_registration, "client_name"))) {
        json_array_append_new(j_error, json_string("client_name is optional and must be a string"));
      }
      if (json_object_get(j_registration, "logo_uri") != NULL && 0 != o_strncmp("https://", json_string_value(json_object_get(j_registration, "logo_uri")), o_strlen("https://")) && 0 != o_strncmp("http://", json_string_value(json_object_get(j_registration, "logo_uri")), o_strlen("http://"))) {
        json_array_append_new(j_error, json_string("logo_uri is optional and must be a string"));
      }
      if (json_object_get(j_registration, "client_uri") != NULL && 0 != o_strncmp("https://", json_string_value(json_object_get(j_registration, "client_uri")), o_strlen("https://")) && 0 != o_strncmp("http://", json_string_value(json_object_get(j_registration, "client_uri")), o_strlen("http://"))) {
        json_array_append_new(j_error, json_string("client_uri is optional and must be a string"));
      }
      if (json_object_get(j_registration, "policy_uri") != NULL && 0 != o_strncmp("https://", json_string_value(json_object_get(j_registration, "policy_uri")), o_strlen("https://")) && 0 != o_strncmp("http://", json_string_value(json_object_get(j_registration, "policy_uri")), o_strlen("http://"))) {
        json_array_append_new(j_error, json_string("policy_uri is optional and must be a string"));
      }
      if (json_object_get(j_registration, "tos_uri") != NULL && 0 != o_strncmp("https://", json_string_value(json_object_get(j_registration, "tos_uri")), o_strlen("https://")) && 0 != o_strncmp("http://", json_string_value(json_object_get(j_registration, "tos_uri")), o_strlen("http://"))) {
        json_array_append_new(j_error, json_string("tos_uri is optional and must be a string"));
      }
      if (json_object_get(j_registration, "jwks_uri") != NULL) {
        if (0 != o_strncmp("https://", json_string_value(json_object_get(j_registration, "jwks_uri")), o_strlen("https://"))) {
          json_array_append_new(j_error, json_string("jwks_uri is optional and must be an https:// url"));
        } else {
          r_jwks_init(&jwks);
          if (r_jwks_import_from_uri(jwks, json_string_value(json_object_get(j_registration, "jwks_uri")), config->x5u_flags) != RHN_OK) {
            json_array_append_new(j_error, json_string("Invalid JWKS pointed by jwks_uri"));
          }
          r_jwks_free(jwks);
        }
      }
      if (json_object_get(j_registration, "jwks") != NULL) {
        r_jwks_init(&jwks);
        if (r_jwks_import_from_json_t(jwks, json_object_get(j_registration, "jwks")) != RHN_OK) {
          json_array_append_new(j_error, json_string("Invalid jwks"));
        }
        r_jwks_free(jwks);
      }
      if (json_object_get(j_registration, "jwks_uri") != NULL && json_object_get(j_registration, "jwks") != NULL) {
        json_array_append_new(j_error, json_string("Invalid parameters, jwks_uri and jwks can't coexist"));
      }
      if (json_object_get(j_registration, "sector_identifier_uri") != NULL && 0 != o_strncmp("https://", json_string_value(json_object_get(j_registration, "sector_identifier_uri")), o_strlen("https://"))) {
        json_array_append_new(j_error, json_string("sector_identifier_uri is optional and must be an https:// uri"));
      }
    } else {
      json_array_append_new(j_error, json_string("registration parameter must be a JSON object"));
    }
    if (json_array_size(j_error)) {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error);
    } else {
      j_return = json_pack("{si}", "result", G_OK);
    }
    json_decref(j_error);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_client_registration_valid - Error allocating resources for j_error");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

static void build_form_post_error_response(struct _u_map * map, struct _u_response * response, ...) {
  va_list vl;
  const char * key, * value;
  char * key_encoded, * value_encoded;
  char * form_output;
  
  form_output = msprintf("<html><head><title>Glewlwyd</title></head><body onload=\"javascript:document.forms[0].submit()\"><form method=\"post\" action=\"%s\">", u_map_get(map, "redirect_uri"));
  
  if (u_map_has_key_case(map, "state")) {
    value_encoded = url_encode(u_map_get(map, "state"));
    form_output = mstrcatf(form_output, "<input type=\"hidden\" name=\"state\" value=\"%s\"/>", value_encoded);
    o_free(value_encoded);
  }
  va_start(vl, response);
  for (key = va_arg(vl, const char *); key != NULL; key = va_arg(vl, const char *)) {
    value = va_arg(vl, const char *);
    key_encoded = url_encode(key);
    if (o_strlen(value)) {
      value_encoded = url_encode(value);
      form_output = mstrcatf(form_output, "<input type=\"hidden\" name=\"%s\" value=\"%s\"/>", key_encoded, value_encoded);
      o_free(value_encoded);
    } else {
      form_output = mstrcatf(form_output, "<input type=\"hidden\" name=\"%s\" value=\"\"/>", key_encoded);
    }
    o_free(key_encoded);
  }
  form_output = mstrcatf(form_output, "</form></body></html>");
  ulfius_set_string_body_response(response, 200, form_output);
  o_free(form_output);
  va_end(vl);
}

static void build_form_post_response(const char * redirect_uri, struct _u_map * map_query, struct _u_response * response) {
  const char ** keys = u_map_enum_keys(map_query), * value;
  char * key_encoded, * value_encoded;
  char * form_output;
  size_t i;

  form_output = msprintf("<html><head><title>Glewlwyd</title></head><body onload=\"javascript:document.forms[0].submit()\"><form method=\"post\" action=\"%s\">", redirect_uri);
  
  for (i=0; keys[i] != NULL; i++) {
    key_encoded = url_encode(keys[i]);
    if (o_strlen((value = u_map_get(map_query, keys[i])))) {
      value_encoded = url_encode(value);
      form_output = mstrcatf(form_output, "<input type=\"hidden\" name=\"%s\" value=\"%s\"/>", key_encoded, value_encoded);
      o_free(value_encoded);
    } else {
      form_output = mstrcatf(form_output, "<input type=\"hidden\" name=\"%s\" value=\"\"/>", key_encoded);
    }
    o_free(key_encoded);
  }
  form_output = mstrcatf(form_output, "</form></body></html>");
  ulfius_set_string_body_response(response, 200, form_output);
  o_free(form_output);
}

static int generate_check_session_iframe(struct _oidc_config * config) {
  if ((config->check_session_iframe = msprintf("<html> <head> <meta charset=\"utf-8\"> <title>Glewlwydcheck_session_iframe</title> </head> <body> iframe </body> <script>function receiveMessage(e){var client_id=e.data.split(' ')[0]; var session_state=e.data.split(' ')[1]; var salt=session_state.split('.')[1]; var request=new XMLHttpRequest(); request.open(\"GET\", \"%s/%s/profile_list/\", true); request.onload=function(){if (this.status===200){var profile_list=JSON.parse(this.response); if (profile_list && profile_list[0]){const encoder=new TextEncoder(); var intermediate=(client_id + \" \" + e.origin + \" \" + profile_list[0].username + \" \" + salt); const data=encoder.encode(intermediate); crypto.subtle.digest('SHA-256', data).then((value)=>{if (session_state==(btoa(new Uint8Array(value).reduce((s, b)=> s + String.fromCharCode(b), ''))+ \".\" + salt)){e.source.postMessage(\"unchanged\", e.origin);}else{e.source.postMessage(\"changed\", e.origin);}})}else{e.source.postMessage(\"error\", e.origin);}}else if (this.status===401){e.source.postMessage(\"changed\", e.origin);}else{e.source.postMessage(\"error\", e.origin);}}; request.onerror=function(){e.source.postMessage(\"error\", e.origin);}; request.send();}; window.addEventListener('message', receiveMessage, false); </script></html>", config->glewlwyd_config->glewlwyd_config->external_url, config->glewlwyd_config->glewlwyd_config->api_prefix)) == NULL) {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_check_session_iframe oidc - Error generating check_session_iframe");
    return G_ERROR;
  } else {
    return G_OK;
  }
}

static char * generate_session_state(const char * client_id, const char * redirect_uri, const char * username) {
  char salt[GLEWLWYD_DEFAULT_SALT_LENGTH+1] = {0}, * session_state = NULL, * origin = NULL, * intermediate = NULL;
  unsigned char intermediate_hash[32] = {0}, intermediate_hash_b64[64] = {0};
  size_t intermediate_hash_len = 32, intermediate_hash_b64_len = 0;
  
  if (o_strlen(client_id) && (0 == o_strncmp(redirect_uri, "http://", o_strlen("http://")) || 0 == o_strncmp(redirect_uri, "https://", o_strlen("https://"))) && o_strlen(username)) {
    origin = o_strdup(redirect_uri);
    *(o_strchr(o_strstr(origin, "://")+3, '/')) = '\0';
    rand_string_nonce(salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
    intermediate = msprintf("%s %s %s %s", client_id, origin, username, salt);
    if (generate_digest_raw(digest_SHA256, (const unsigned char *)intermediate, o_strlen(intermediate), intermediate_hash, &intermediate_hash_len)) {
      if (o_base64_encode(intermediate_hash, intermediate_hash_len, intermediate_hash_b64, &intermediate_hash_b64_len)) {
        intermediate_hash_b64[intermediate_hash_b64_len] = '\0';
        session_state = msprintf("%s.%s", intermediate_hash_b64, salt);
      }
    }
    o_free(intermediate);
    o_free(origin);
  }
  return session_state;
}

static int generate_discovery_content(struct _oidc_config * config) {
  json_t * j_discovery = json_object(), * j_element = NULL, * j_rhon_info = r_library_info_json_t(), * j_sign_pubkey = json_array();
  char * plugin_url = config->glewlwyd_config->glewlwyd_callback_get_plugin_external_url(config->glewlwyd_config, config->name);
  size_t index = 0;
  int ret = G_OK;
  jwk_t * jwk;
  
  if (j_discovery != NULL && j_sign_pubkey != NULL && plugin_url != NULL) {
    json_object_set(j_discovery, "issuer", json_object_get(config->j_params, "iss"));
    json_object_set_new(j_discovery, "authorization_endpoint", json_pack("s+", plugin_url, "/auth"));
    json_object_set_new(j_discovery, "token_endpoint", json_pack("s+", plugin_url, "/token"));
    json_object_set_new(j_discovery, "userinfo_endpoint", json_pack("s+", plugin_url, "/userinfo"));
    json_object_set_new(j_discovery, "jwks_uri", json_pack("s+", plugin_url, "/jwks"));
    json_object_set_new(j_discovery, "token_endpoint_auth_methods_supported", json_pack("[ss]", "client_secret_basic", "client_secret_post"));
    
    json_object_set_new(j_discovery, "id_token_signing_alg_values_supported", json_pack("[s]", r_jwa_alg_to_str(r_jwt_get_sign_alg(config->jwt_sign))));
    json_object_set_new(j_discovery, "userinfo_signing_alg_values_supported", json_pack("[s]", r_jwa_alg_to_str(r_jwt_get_sign_alg(config->jwt_sign))));
    for (index=0; index<r_jwks_size(config->jwt_sign->jwks_privkey_sign); index++) {
      jwk = r_jwks_get_at(config->jwt_sign->jwks_privkey_sign, index);
      if (!json_array_has_string(json_object_get(j_discovery, "id_token_signing_alg_values_supported"), r_jwk_get_property_str(jwk, "alg"))) {
        json_array_append_new(json_object_get(j_discovery, "id_token_signing_alg_values_supported"), json_string(r_jwk_get_property_str(jwk, "alg")));
        json_array_append_new(json_object_get(j_discovery, "userinfo_signing_alg_values_supported"), json_string(r_jwk_get_property_str(jwk, "alg")));
      }
      r_jwk_free(jwk);
    }
    json_object_set(j_discovery, "userinfo_encryption_alg_values_supported", json_object_get(json_object_get(j_rhon_info, "jwe"), "alg"));
    json_object_set(j_discovery, "userinfo_encryption_enc_values_supported", json_object_get(json_object_get(j_rhon_info, "jwe"), "enc"));
    if (json_object_get(config->j_params, "request-parameter-allow") == json_true()) {
      json_array_foreach(json_object_get(json_object_get(j_rhon_info, "jws"), "alg"), index, j_element) {
        if (0 != o_strncmp("HS", json_string_value(j_element), 2) && 0 != o_strcmp("none", json_string_value(j_element))) {
          json_array_append(j_sign_pubkey, j_element);
        }
      }
      json_object_set_new(j_discovery, "request_object_signing_alg_values_supported", json_pack("[ssss]", "none", "HS256", "HS384", "HS512"));
      json_object_set(j_discovery, "request_object_encryption_alg_values_supported", json_object_get(json_object_get(j_rhon_info, "jwe"), "alg"));
      json_object_set(j_discovery, "request_object_encryption_enc_values_supported", json_object_get(json_object_get(j_rhon_info, "jwe"), "enc"));
      json_array_append_new(json_object_get(j_discovery, "token_endpoint_auth_methods_supported"), json_string("client_secret_jwt"));
      json_object_set_new(j_discovery, "token_endpoint_auth_signing_alg_values_supported", json_pack("[sss]", "HS256", "HS384", "HS512"));
      if (json_string_length(json_object_get(config->j_params, "client-pubkey-parameter")) || json_string_length(json_object_get(config->j_params, "client-jwks-parameter")) || json_string_length(json_object_get(config->j_params, "client-jwks_uri-parameter"))) {
        json_array_extend(json_object_get(j_discovery, "request_object_signing_alg_values_supported"), j_sign_pubkey);
        json_array_extend(json_object_get(j_discovery, "token_endpoint_auth_signing_alg_values_supported"), j_sign_pubkey);
        json_array_append_new(json_object_get(j_discovery, "token_endpoint_auth_methods_supported"), json_string("private_key_jwt"));
      }
    }
    if (json_object_get(config->j_params, "allowed-scope") != NULL && json_array_size(json_object_get(config->j_params, "allowed-scope"))) {
      json_object_set(j_discovery, "scopes_supported", json_object_get(config->j_params, "allowed-scope"));
    } else {
      json_object_set_new(j_discovery, "scopes_supported", json_pack("[s]", "openid"));
    }
    json_object_set_new(j_discovery, "response_types_supported", json_array());
    if (config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE]) {
      json_array_append_new(json_object_get(j_discovery, "response_types_supported"), json_string("code"));
    }
    if (config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN]) {
      json_array_append_new(json_object_get(j_discovery, "response_types_supported"), json_string("id_token"));
    }
    if (config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN] && config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_TOKEN]) {
      json_array_append_new(json_object_get(j_discovery, "response_types_supported"), json_string("token id_token"));
    }
    if (config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN] && config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE]) {
      json_array_append_new(json_object_get(j_discovery, "response_types_supported"), json_string("code id_token"));
    }
    if (config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN] && config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE] && config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_TOKEN]) {
      json_array_append_new(json_object_get(j_discovery, "response_types_supported"), json_string("code token id_token"));
    }
    if (config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_NONE]) {
      json_array_append_new(json_object_get(j_discovery, "response_types_supported"), json_string("none"));
    }
    if (config->allow_non_oidc && config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS]) {
      json_array_append_new(json_object_get(j_discovery, "response_types_supported"), json_string("password"));
    }
    if (config->allow_non_oidc && config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_TOKEN]) {
      json_array_append_new(json_object_get(j_discovery, "response_types_supported"), json_string("token"));
    }
    if (config->allow_non_oidc && config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS]) {
      json_array_append_new(json_object_get(j_discovery, "response_types_supported"), json_string("client_credentials"));
    }
    if (config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN]) {
      json_array_append_new(json_object_get(j_discovery, "response_types_supported"), json_string("refresh_token"));
    }
    json_object_set_new(j_discovery, "response_modes_supported", json_pack("[sss]", "query", "fragment", "form_post"));
    json_object_set_new(j_discovery, "grant_types_supported", json_pack("[ss]", "authorization_code", "implicit"));
    json_object_set_new(j_discovery, "display_values_supported", json_pack("[ssss]", "page", "popup", "touch", "wap"));
    json_object_set_new(j_discovery, "claim_types_supported", json_pack("[s]", "normal"));
    json_object_set_new(j_discovery, "claims_parameter_supported", json_true());
    json_object_set_new(j_discovery, "claims_supported", json_array());
    json_array_foreach(json_object_get(config->j_params, "claims"), index, j_element) {
      json_array_append(json_object_get(j_discovery, "claims_supported"), json_object_get(j_element, "name"));
    }
    if (0 == o_strcmp("on-demand", json_string_value(json_object_get(config->j_params, "name-claim"))) || 0 == o_strcmp("mandatory", json_string_value(json_object_get(config->j_params, "name-claim")))) {
      json_array_append_new(json_object_get(j_discovery, "claims_supported"), json_string("name"));
    }
    if (0 == o_strcmp("on-demand", json_string_value(json_object_get(config->j_params, "email-claim"))) || 0 == o_strcmp("mandatory", json_string_value(json_object_get(config->j_params, "email-claim")))) {
      json_array_append_new(json_object_get(j_discovery, "claims_supported"), json_string("email"));
    }
    if (0 == o_strcmp("on-demand", json_string_value(json_object_get(json_object_get(config->j_params, "address-claim"), "type"))) || 0 == o_strcmp("mandatory", json_string_value(json_object_get(json_object_get(config->j_params, "address-claim"), "type")))) {
      json_array_append_new(json_object_get(j_discovery, "claims_supported"), json_string("address"));
    }
    if (json_string_length(json_object_get(config->j_params, "service-documentation"))) {
      json_object_set(j_discovery, "service_documentation", json_object_get(config->j_params, "service-documentation"));
    }
    json_object_set_new(j_discovery, "ui_locales_supported", json_pack("[sss]", "en", "fr", "nl"));
    json_object_set(j_discovery, "request_parameter_supported", json_object_get(config->j_params, "request-parameter-allow")==json_false()?json_false():json_true());
    json_object_set(j_discovery, "request_uri_parameter_supported", json_object_get(config->j_params, "request-parameter-allow")==json_false()?json_false():json_true());
    json_object_set_new(j_discovery, "require_request_uri_registration", json_false());
    if (json_string_length(json_object_get(config->j_params, "op-policy-uri"))) {
      json_object_set(j_discovery, "op_policy_uri", json_object_get(config->j_params, "op-policy-uri"));
    }
    if (json_string_length(json_object_get(config->j_params, "op-tos-uri"))) {
      json_object_set(j_discovery, "op_tos_uri", json_object_get(config->j_params, "op-tos-uri"));
    }
    if (config->subject_type == GLEWLWYD_OIDC_SUBJECT_TYPE_PAIRWISE) {
      json_object_set_new(j_discovery, "subject_types_supported", json_pack("[s]", "pairwise"));
    } else {
      json_object_set_new(j_discovery, "subject_types_supported", json_pack("[s]", "public"));
    }
    if (json_object_get(config->j_params, "pkce-allowed") == json_true()) {
      json_object_set_new(j_discovery, "code_challenge_methods_supported", json_pack("[s]", "S256"));
      if (json_object_get(config->j_params, "pkce-method-plain-allowed") == json_true()) {
        json_array_append_new(json_object_get(j_discovery, "code_challenge_methods_supported"), json_string("plain"));
      }
    }
    if (json_object_get(config->j_params, "introspection-revocation-allowed") == json_true()) {
      json_object_set_new(j_discovery, "revocation_endpoint", json_pack("s+", plugin_url, "/revoke"));
      json_object_set_new(j_discovery, "introspection_endpoint", json_pack("s+", plugin_url, "/introspect"));
      json_object_set_new(j_discovery, "revocation_endpoint_auth_methods_supported", json_array());
      json_object_set_new(j_discovery, "introspection_endpoint_auth_methods_supported", json_array());
      json_object_set_new(j_discovery, "introspection_endpoint_signing_alg_values_supported", json_pack("[s]", r_jwa_alg_to_str(r_jwt_get_sign_alg(config->jwt_sign))));
      for (index=0; index<r_jwks_size(config->jwt_sign->jwks_privkey_sign); index++) {
        jwk = r_jwks_get_at(config->jwt_sign->jwks_privkey_sign, index);
        if (!json_array_has_string(json_object_get(j_discovery, "introspection_endpoint_signing_alg_values_supported"), r_jwk_get_property_str(jwk, "alg"))) {
          json_array_append_new(json_object_get(j_discovery, "introspection_endpoint_signing_alg_values_supported"), json_string(r_jwk_get_property_str(jwk, "alg")));
        }
        r_jwk_free(jwk);
      }
      json_object_set(j_discovery, "introspection_endpoint_encryption_alg_values_supported", json_object_get(json_object_get(j_rhon_info, "jwe"), "alg"));
      json_object_set(j_discovery, "introspection_endpoint_encryption_enc_values_supported", json_object_get(json_object_get(j_rhon_info, "jwe"), "enc"));
      if (json_object_get(config->j_params, "introspection-revocation-allow-target-client") == json_true()) {
        json_array_append_new(json_object_get(j_discovery, "revocation_endpoint_auth_methods_supported"), json_string("client_secret_basic"));
        json_array_append_new(json_object_get(j_discovery, "introspection_endpoint_auth_methods_supported"), json_string("client_secret_basic"));
      }
      if (o_strlen(config->introspect_revoke_resource_config->oauth_scope)) {
        json_array_append_new(json_object_get(j_discovery, "revocation_endpoint_auth_methods_supported"), json_string("bearer"));
        json_array_append_new(json_object_get(j_discovery, "introspection_endpoint_auth_methods_supported"), json_string("bearer"));
      }
    }
    if (json_object_get(config->j_params, "register-client-allowed") == json_true()) {
      json_object_set_new(j_discovery, "registration_endpoint", json_pack("s+", plugin_url, "/register"));
    }
    if (json_object_get(config->j_params, "session-management-allowed") == json_true()) {
      json_object_set_new(j_discovery, "end_session_endpoint", json_pack("s+", plugin_url, "/end_session"));
      json_object_set_new(j_discovery, "check_session_iframe", json_pack("s+", plugin_url, "/check_session_iframe"));
    }
    config->discovery_str = json_dumps(j_discovery, JSON_COMPACT);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_discovery_content - Error allocating resources for j_discovery");
    ret = G_ERROR;
  }
  json_decref(j_discovery);
  json_decref(j_sign_pubkey);
  json_decref(j_rhon_info);
  o_free(plugin_url);
  return ret;
}

static int callback_client_registration(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  json_t * j_result_check, * j_result, * j_registration = ulfius_get_json_body_request(request, NULL);
  
  j_result_check = is_client_registration_valid(config, j_registration);
  if (check_result_value(j_result_check, G_OK)) {
    j_result = client_register(config, request, j_registration);
    if (check_result_value(j_result, G_OK)) {
      ulfius_set_json_body_response(response, 200, json_object_get(j_result, "client"));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_client_registration - Error client_register");
      response->status = 500;
    }
    json_decref(j_result);
  } else if (check_result_value(j_result_check, G_ERROR_PARAM)) {
    ulfius_set_json_body_response(response, 400, json_object_get(j_result_check, "error"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_client_registration - Error is_client_registration_valid");
    response->status = 500;
  }
  json_decref(j_result_check);
  json_decref(j_registration);
  return U_CALLBACK_CONTINUE;
}

static int callback_check_registration(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  json_t * j_introspect;
  int ret = U_CALLBACK_UNAUTHORIZED;
  
  if (config->client_register_resource_config->oauth_scope == NULL) {
    ret = U_CALLBACK_CONTINUE;
  } else if (u_map_get_case(request->map_header, "Authorization")) {
    j_introspect = get_token_metadata(config, (u_map_get_case(request->map_header, "Authorization") + o_strlen(HEADER_PREFIX_BEARER)), "access_token", NULL);
    if (check_result_value(j_introspect, G_OK) && json_object_get(json_object_get(j_introspect, "token"), "active") == json_true()) {
      ret = callback_check_glewlwyd_oidc_access_token(request, response, (void*)config->client_register_resource_config);
    }
    json_decref(j_introspect);
  }
  return ret;
}

static int callback_revocation(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  json_t * j_result = get_token_metadata(config, u_map_get(request->map_post_body, "token"), u_map_get(request->map_post_body, "token_type_hint"), get_client_id_for_introspection(config, request));
  
  if (check_result_value(j_result, G_OK)) {
    if (json_object_get(json_object_get(j_result, "token"), "active") == json_true()) {
      if (0 == o_strcmp("refresh_token", json_string_value(json_object_get(json_object_get(j_result, "token"), "token_type")))) {
        if (revoke_refresh_token(config, u_map_get(request->map_post_body, "token")) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_revocation  - Error revoke_refresh_token");
          response->status = 500;
        }
      } else if (0 == o_strcmp("access_token", json_string_value(json_object_get(json_object_get(j_result, "token"), "token_type")))) {
        if (revoke_access_token(config, u_map_get(request->map_post_body, "token")) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_revocation  - Error revoke_access_token");
          response->status = 500;
        }
      } else {
        if (revoke_id_token(config, u_map_get(request->map_post_body, "token")) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_revocation  - Error revoke_id_token");
          response->status = 500;
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
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  json_t * j_result = get_token_metadata(config, u_map_get(request->map_post_body, "token"), u_map_get(request->map_post_body, "token_type_hint"), get_client_id_for_introspection(config, request));
  jwt_t * jwt = NULL;
  jwk_t * jwk = NULL;
  time_t now;
  const char * sign_kid = json_string_value(json_object_get(config->j_params, "client-sign_kid-parameter"));
  char * token = NULL, * token_out;
  
  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");

  if (check_result_value(j_result, G_OK)) {
    if (0 == o_strcmp("jwt", u_map_get(request->map_url, "format")) || 0 == o_strcmp("jwt", u_map_get(request->map_post_body, "format")) || 0 == o_strcasecmp("application/jwt", u_map_get(request->map_header, "Accept"))) {
      if (0 == o_strcmp("access_token", json_string_value(json_object_get(json_object_get(j_result, "token"), "token_type")))) {
        if ((jwt = r_jwt_copy(config->jwt_sign)) != NULL) {
          time(&now);
          json_object_set(json_object_get(j_result, "token"), "iss", json_object_get(config->j_params, "iss"));
          json_object_set_new(json_object_get(j_result, "token"), "iat", json_integer(now));
          if (r_jwt_set_full_claims_json_t(jwt, json_object_get(j_result, "token")) == RHN_OK) {
            r_jwt_set_header_str_value(jwt, "typ", "introspection+jwt");
            if (json_string_length(json_object_get(json_object_get(j_result, "client"), sign_kid))) {
              jwk = r_jwks_get_by_kid(config->jwt_sign->jwks_privkey_sign, json_string_value(json_object_get(json_object_get(j_result, "client"), sign_kid)));
            } else {
              jwk = r_jwk_copy(config->jwk_sign_default);
            }
            token = r_jwt_serialize_signed(jwt, jwk, 0);
            r_jwk_free(jwk);
            if (token != NULL) {
              if ((token_out = encrypt_token_if_required(config, token, json_object_get(j_result, "client"), GLEWLWYD_TOKEN_TYPE_USERINFO)) != NULL) {
                ulfius_set_string_body_response(response, 200, token_out);
                u_map_put(response->map_header, "Content-Type", "application/jwt");
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "callback_introspection oidc - Error encrypt_token_if_required");
                response->status = 500;
              }
              o_free(token_out);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "callback_introspection oidc - Error r_jwt_serialize_signed");
              response->status = 500;
            }
            o_free(token);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "callback_introspection - Error r_jwt_set_full_claims_json_t");
            response->status = 500;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "callback_introspection - Error r_jwt_copy");
          response->status = 500;
        }
        r_jwt_free(jwt);
      } else {
        // token introspection forbidden if token_type isn't access_token
        response->status = 400;
      }
    } else {
      ulfius_set_json_body_response(response, 200, json_object_get(j_result, "token"));
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

static int callback_check_intropect_revoke(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  json_t * j_client, * j_element = NULL, * j_introspect;
  size_t index = 0;
  int ret = U_CALLBACK_UNAUTHORIZED;
  
  if (u_map_get_case(request->map_header, "Authorization") != NULL && config->introspect_revoke_resource_config->oauth_scope != NULL) {
    j_introspect = get_token_metadata(config, (u_map_get_case(request->map_header, "Authorization") + o_strlen(HEADER_PREFIX_BEARER)), "access_token", NULL);
    if (check_result_value(j_introspect, G_OK) && json_object_get(json_object_get(j_introspect, "token"), "active") == json_true()) {
      ret = callback_check_glewlwyd_oidc_access_token(request, response, (void*)config->introspect_revoke_resource_config);
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
 * Process all the input parameter, data and context to validate or not an authentication request
 */
static json_t * validate_endpoint_auth(const struct _u_request * request, struct _u_response * response, void * user_data, int auth_type, json_t * j_request, json_t * j_client_validated) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  char * redirect_url = NULL, * issued_for = NULL, ** scope_list = NULL, * state_param, * endptr = NULL, * id_token_hash = NULL, code_challenge_stored[GLEWLWYD_CODE_CHALLENGE_MAX_LENGTH + 1] = {0};
  const char * client_id = NULL, * redirect_uri = NULL, * scope = NULL, * display = NULL, * ui_locales = NULL, * login_hint = NULL, * prompt = NULL, * nonce = NULL, * max_age = NULL, * id_token_hint = NULL, * code_challenge = NULL, * code_challenge_method = NULL, * ip_source = get_ip_source(request);
  json_t * j_session = NULL, * j_client = NULL, * j_last_token = NULL, * j_claims = NULL;
  json_t * j_return;
  struct _u_map additional_parameters;
  long int l_max_age;
  time_t now;
  int res;
  struct _u_map * map = get_map(request);
  int form_post;
  jwt_t * jwt = NULL;
  jwk_t * jwk = NULL, * jwk_id_token = NULL;
  const char * sign_kid = json_string_value(json_object_get(config->j_params, "client-sign_kid-parameter"));
  
  additional_parameters.nb_values = 0;
  additional_parameters.keys = NULL;
  additional_parameters.values = NULL;
  additional_parameters.lengths = NULL;
  
  state_param = get_state_param(u_map_get(map, "state"));
  
  // Let's use again the loop do {} while (false); to avoid too much embeded if statements
  do {
    form_post = (0 == o_strcmp("form_post", u_map_get(map, "response_mode")));
    
    if (u_map_init(&additional_parameters) != U_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_endpoint_auth - Error u_map_init");
      if (form_post) {
        build_form_post_error_response(map, response, "error", "server_error", NULL);
      } else {
        response->status = 302;
        redirect_url = msprintf("%s%serror=server_error%s", u_map_get(map, "redirect_uri"), (o_strchr(u_map_get(map, "redirect_uri"), '?')!=NULL?"&":"?"), state_param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
      j_return = json_pack("{si}", "result", G_ERROR);
      break;
    }
    
    if (u_map_has_key(map, "client_id")) {
      client_id = u_map_get(map, "client_id");
    }
    if (u_map_has_key(map, "redirect_uri")) {
      redirect_uri = u_map_get(map, "redirect_uri");
    }
    if (u_map_has_key(map, "scope")) {
      scope = u_map_get(map, "scope");
    }
    if (u_map_has_key(map, "display")) {
      display = u_map_get(map, "display");
    }
    if (u_map_has_key(map, "ui_locales")) {
      ui_locales = u_map_get(map, "ui_locales");
    }
    if (u_map_has_key(map, "login_hint")) {
      login_hint = u_map_get(map, "login_hint");
    }
    if (u_map_has_key(map, "prompt")) {
      prompt = u_map_get(map, "prompt");
    }
    if (u_map_has_key(map, "max_age")) {
      max_age = u_map_get(map, "max_age");
    }
    if (u_map_has_key(map, "id_token_hint")) {
      id_token_hint = u_map_get(map, "id_token_hint");
    }
    if (u_map_has_key(map, "code_challenge")) {
      code_challenge = u_map_get(map, "code_challenge");
    }
    if (u_map_has_key(map, "code_challenge_method")) {
      code_challenge_method = u_map_get(map, "code_challenge_method");
    }
    if (u_map_has_key(map, "claims") && o_strlen(u_map_get(map, "claims"))) {
      j_claims = json_loads(u_map_get(map, "claims"), JSON_DECODE_ANY, NULL);
      if (j_claims == NULL) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - error claims parameter not in JSON format, origin: %s", ip_source);
        if (form_post) {
          build_form_post_error_response(map, response, "error", "invalid_request", NULL);
        } else {
          response->status = 302;
          redirect_url = msprintf("%s%serror=invalid_request%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        break;
      }
    }
    if (j_request != NULL) {
      client_id = json_string_value(json_object_get(j_request, "client_id"));
      redirect_uri = json_string_value(json_object_get(j_request, "redirect_uri"));
      scope = json_string_value(json_object_get(j_request, "scope"));
      display = json_string_value(json_object_get(j_request, "display"));
      ui_locales = json_string_value(json_object_get(j_request, "ui_locales"));
      login_hint = json_string_value(json_object_get(j_request, "login_hint"));
      prompt = json_string_value(json_object_get(j_request, "prompt"));
      nonce = json_string_value(json_object_get(j_request, "nonce"));
      max_age = json_string_value(json_object_get(j_request, "max_age"));
      id_token_hint = json_string_value(json_object_get(j_request, "id_token_hint"));
      j_claims = json_incref(json_object_get(j_request, "claims"));
      code_challenge = json_string_value(json_object_get(j_request, "code_challenge"));
      code_challenge_method = json_string_value(json_object_get(j_request, "code_challenge_method"));
      if (state_param == NULL) {
        state_param = get_state_param(json_string_value(json_object_get(j_request, "state")));
      }
    }
    if (u_map_has_key(map, "nonce")) {
      nonce = u_map_get(map, "nonce");
    }
    
    if (!o_strlen(redirect_uri)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - redirect_uri missing, origin: %s", ip_source);
      response->status = 403;
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }
    
    // Check if client is allowed to perform this request
    if (j_client_validated == NULL) {
      j_client = check_client_valid(config, client_id, request->auth_basic_user, request->auth_basic_password, client_id, u_map_get(map, "client_secret"), u_map_get(map, "redirect_uri"), auth_type, 1, ip_source);
      if (!check_result_value(j_client, G_OK)) {
        // client is not authorized
        if (form_post) {
          build_form_post_error_response(map, response, "error", "unauthorized_client", NULL);
        } else {
          response->status = 302;
          redirect_url = msprintf("%s%serror=unauthorized_client%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        break;
      }
    } else {
      j_client = check_client_valid_without_secret(config, client_id, redirect_uri, auth_type, ip_source);
      if (!check_result_value(j_client, G_OK)) {
        // client is not authorized
        if (form_post) {
          build_form_post_error_response(map, response, "error", "unauthorized_client", NULL);
        } else {
          response->status = 302;
          redirect_url = msprintf("%s%serror=unauthorized_client%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        break;
      }
    }

    if (display != NULL) {
      u_map_put(&additional_parameters, "display", display);
    }
    
    if (ui_locales != NULL) {
      u_map_put(&additional_parameters, "ui_locales", ui_locales);
    }
    
    if (login_hint != NULL) {
      u_map_put(&additional_parameters, "login_hint", login_hint);
    }
    
    if (j_claims != NULL && parse_claims_request(j_claims) != G_OK) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - error parsing claims parameter, origin: %s", ip_source);
      if (form_post) {
        build_form_post_error_response(map, response, "error", "invalid_request", NULL);
      } else {
        response->status = 302;
        redirect_url = msprintf("%s%serror=invalid_request%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }
    
    // Check code_challenge if necessary
    if ((res = is_code_challenge_valid(config, code_challenge, code_challenge_method, code_challenge_stored)) == G_ERROR_PARAM) {
      if (form_post) {
        build_form_post_error_response(map, response, "error", "invalid_request", NULL);
      } else {
        response->status = 302;
        redirect_url = msprintf("%s%serror=invalid_request%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    } else if (res != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_endpoint_auth - error is_code_challenge_valid");
      if (form_post) {
        build_form_post_error_response(map, response, "error", "server_error", NULL);
      } else {
        response->status = 302;
        redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }
    
    if (!u_map_has_key(map, "g_continue") && (0 == o_strcmp("login", prompt) || 0 == o_strcmp("consent", prompt) || 0 == o_strcmp("select_account", prompt))) {
      // Redirect to login page
      u_map_put(&additional_parameters, "prompt", prompt);
      redirect_url = get_login_url(config, request, "auth", client_id, scope, &additional_parameters);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      response->status = 302;
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }
    
    // Check if the query parameter 'g_continue' exists, otherwise redirect to login page
    if (!u_map_has_key(map, "g_continue") && 0 != o_strcmp("none", prompt)) {
      // Redirect to login page
      response->status = 302;
      redirect_url = get_login_url(config, request, "auth", client_id, scope, &additional_parameters);
      ulfius_add_header_to_response(response, "Location", redirect_url);
      o_free(redirect_url);
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }
    
    // Check if at least one scope has been provided
    if (!o_strlen(scope)) {
      // Scope is not allowed for this user
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - scope list is missing or empty or scope 'openid' missing, origin: %s", ip_source);
      if (form_post) {
        build_form_post_error_response(map, response, "error", "invalid_scope", NULL);
      } else {
        response->status = 302;
        redirect_url = msprintf("%s%serror=invalid_scope%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }

    // Split scope list into scope array
    if (!split_string(scope, " ", &scope_list)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_endpoint_auth - Error split_string");
      if (form_post) {
        build_form_post_error_response(map, response, "error", "server_error", NULL);
      } else {
        response->status = 302;
        redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
      j_return = json_pack("{si}", "result", G_ERROR);
      break;
    }

    // Check that the scope 'openid' is provided, otherwise return error
    if ((!string_array_has_value((const char **)scope_list, "openid") && !config->allow_non_oidc) || (auth_type & GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN_FLAG && !string_array_has_value((const char **)scope_list, "openid"))) {
      // Scope openid missing
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - scope 'openid' missing, origin: %s", ip_source);
      if (form_post) {
        build_form_post_error_response(map, response, "error", "invalid_scope", NULL);
      } else {
        response->status = 302;
        redirect_url = msprintf("%s%serror=invalid_scope%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }

    // Check that the session is valid for this user with this scope list
    j_session = validate_session_client_scope(config, request, client_id, scope);
    if (check_result_value(j_session, G_ERROR_NOT_FOUND)) {
      if (0 == o_strcmp("none", prompt)) {
        // Scope is not allowed for this user
        y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - prompt 'none', avoid login page, origin: %s", ip_source);
        if (form_post) {
          build_form_post_error_response(map, response, "error", "interaction_required", NULL);
        } else {
          response->status = 302;
          redirect_url = msprintf("%s%serror=interaction_required%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      } else {
        // Redirect to login page
        response->status = 302;
        redirect_url = get_login_url(config, request, "auth", client_id, scope, &additional_parameters);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
      break;
    } else if (check_result_value(j_session, G_ERROR_UNAUTHORIZED)) {
      if (0 == o_strcmp("none", prompt)) {
        // Scope is not allowed for this user
        y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - prompt 'none', avoid login page, origin: %s", ip_source);
        if (form_post) {
          build_form_post_error_response(map, response, "error", "interaction_required", NULL);
        } else {
          response->status = 302;
          redirect_url = msprintf("%s%serror=interaction_required%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      } else {
        // Scope is not allowed for this user
        y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - scope list '%s' is invalid for user '%s', origin: %s", scope, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), ip_source);
        if (form_post) {
          build_form_post_error_response(map, response, "error", "invalid_scope", NULL);
        } else {
          response->status = 302;
          redirect_url = msprintf("%s%serror=invalid_scope%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
      break;
    } else if (!check_result_value(j_session, G_OK)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_endpoint_auth - Error validate_session_client_scope");
      if (form_post) {
        build_form_post_error_response(map, response, "error", "server_error", NULL);
      } else {
        response->status = 302;
        redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
      }
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      break;
    }
    
    // If parameter prompt=none is set, id_token_hint must be set and correspond to the last id_token provided by the client for the current user
    if (0 == o_strcmp("none", prompt)) {
      if (o_strlen(id_token_hint)) {
        if (j_client != NULL) {
          if (json_string_length(json_object_get(j_client, sign_kid))) {
            jwk_id_token = r_jwks_get_by_kid(config->oidc_resource_config->jwt->jwks_pubkey_sign, json_string_value(json_object_get(j_client, sign_kid)));
          } else {
            jwk_id_token = r_jwk_copy(config->oidc_resource_config->jwk_verify_default);
          }
        } else {
          jwk_id_token = r_jwk_copy(config->oidc_resource_config->jwk_verify_default);
        }
        if ((jwt = r_jwt_copy(config->oidc_resource_config->jwt)) != NULL && r_jwt_parse(jwt, id_token_hint, 0) == RHN_OK && r_jwt_verify_signature(jwt, jwk_id_token, 0) == RHN_OK) {
          j_last_token = get_last_id_token(config, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), client_id);
          if (check_result_value(j_last_token, G_OK)) {
            id_token_hash = config->glewlwyd_config->glewlwyd_callback_generate_hash(config->glewlwyd_config, id_token_hint);
            if (0 != o_strcmp(id_token_hash, json_string_value(json_object_get(json_object_get(j_last_token, "id_token"), "token_hash")))) {
              y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - id_token_hint was not the last one provided to client '%s' for user '%s', origin: %s", client_id, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), ip_source);
              if (form_post) {
                build_form_post_error_response(map, response, "error", "invalid_request", NULL);
              } else {
                response->status = 302;
                redirect_url = msprintf("%s%serror=invalid_request%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
              }
              j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
              break;
            }
          } else if (check_result_value(j_last_token, G_ERROR_NOT_FOUND)) {
            y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - no id_token was provided to client '%s' for user '%s', origin: %s", client_id, json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")), ip_source);
            if (form_post) {
              build_form_post_error_response(map, response, "error", "invalid_request", NULL);
            } else {
              response->status = 302;
              redirect_url = msprintf("%s%serror=invalid_request%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
            }
            j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
            break;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_endpoint_auth - Error get_last_id_token");
            if (form_post) {
              build_form_post_error_response(map, response, "error", "server_error", NULL);
            } else {
              response->status = 302;
              redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
              ulfius_add_header_to_response(response, "Location", redirect_url);
              o_free(redirect_url);
            }
            j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
            break;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - id_token has invalid content or signature, origin: %s", ip_source);
          if (form_post) {
            build_form_post_error_response(map, response, "error", "invalid_request", NULL);
          } else {
            response->status = 302;
            redirect_url = msprintf("%s%serror=invalid_request%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
          }
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          break;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - no id_token provided in the request, origin: %s", ip_source);
        if (form_post) {
          build_form_post_error_response(map, response, "error", "invalid_request", NULL);
        } else {
          response->status = 302;
          redirect_url = msprintf("%s%serror=invalid_request%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
        break;
      }
    }

    // Session may be valid but another level of authentication may be requested
    if (json_object_get(json_object_get(j_session, "session"), "authorization_required") == json_true()) {
      if (0 == o_strcmp("none", prompt)) {
        // Scope is not allowed for this user
        y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - prompt 'none', avoid login page, origin: %s", ip_source);
        if (form_post) {
          build_form_post_error_response(map, response, "error", "interaction_required", NULL);
        } else {
          response->status = 302;
          redirect_url = msprintf("%s%serror=interaction_required%s", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"), state_param);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      } else {
        // Redirect to login page
        redirect_url = get_login_url(config, request, "auth", client_id, scope, &additional_parameters);
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
        response->status = 302;
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
      break;
    }
    
    issued_for = get_client_hostname(request);
    if (issued_for == NULL) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_endpoint_auth - Error get_client_hostname");
      if (form_post) {
        build_form_post_error_response(map, response, "error", "server_error", NULL);
      } else {
        redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
        response->status = 302;
      }
      j_return = json_pack("{si}", "result", G_ERROR);
      break;
    }
    
    // Trigger the use of this session to reset use of some schemes
    if (config->glewlwyd_config->glewlwyd_callback_trigger_session_used(config->glewlwyd_config, request, json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered"))) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc validate_endpoint_auth - Error glewlwyd_callback_trigger_session_used");
      if (form_post) {
        build_form_post_error_response(map, response, "error", "server_error", NULL);
      } else {
        redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
        response->status = 302;
      }
      j_return = json_pack("{si}", "result", G_ERROR);
      break;
    }
    
    // nonce parameter is required for some authorization types
    if ((auth_type & GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN_FLAG) && !o_strlen(nonce)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - nonce required, origin: %s", ip_source);
      if (form_post) {
        build_form_post_error_response(map, response, "error", "invalid_request", NULL);
      } else {
        redirect_url = msprintf("%s%serror=invalid_request", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
        ulfius_add_header_to_response(response, "Location", redirect_url);
        o_free(redirect_url);
        response->status = 302;
      }
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
      break;
    }
    
    if (o_strlen(max_age)) {
      l_max_age = strtol(max_age, &endptr, 10);
      if (!(*endptr) && l_max_age > 0) {
        time(&now);
        if (l_max_age < (now - config->glewlwyd_config->glewlwyd_callback_get_session_age(config->glewlwyd_config, request, json_string_value(json_object_get(json_object_get(j_session, "session"), "scope_filtered"))))) {
          // Redirect to login page
          u_map_put(&additional_parameters, "refresh_login", "true");
          redirect_url = get_login_url(config, request, "auth", client_id, scope, &additional_parameters);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          response->status = 302;
          j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          break;
        }
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "oidc validate_endpoint_auth - nonce required, origin: %s", ip_source);
        if (form_post) {
          build_form_post_error_response(map, response, "error", "invalid_request", NULL);
        } else {
          redirect_url = msprintf("%s%serror=invalid_request", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
          response->status = 302;
        }
        j_return = json_pack("{si}", "result", G_ERROR_PARAM);
        break;
      }
    }
    
    j_return = json_pack("{sisOsOssss}", "result", G_OK, "session", json_object_get(j_session, "session"), "client", json_object_get(j_client, "client"), "issued_for", issued_for, "code_challenge", code_challenge_stored);
    if (j_claims != NULL) {
      json_object_set(j_return, "claims", j_claims);
    }
  } while (0);

  r_jwk_free(jwk);
  r_jwk_free(jwk_id_token);
  o_free(issued_for);
  o_free(state_param);
  o_free(id_token_hash);
  json_decref(j_session);
  json_decref(j_client);
  json_decref(j_last_token);
  json_decref(j_claims);
  free_string_array(scope_list);
  u_map_clean(&additional_parameters);
  r_jwt_free(jwt);
  
  return j_return;
}

/**
 * The second step of authentiation code
 * Validates if code, client_id and redirect_uri sent are valid, then returns a token set
 */
static int check_auth_type_access_token_request (const struct _u_request * request, struct _u_response * response, void * user_data, json_t * j_assertion_client) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  const char * code = u_map_get(request->map_post_body, "code"), 
             * client_id = u_map_get(request->map_post_body, "client_id"),
             * redirect_uri = u_map_get(request->map_post_body, "redirect_uri"),
             * code_verifier = u_map_get(request->map_post_body, "code_verifier"),
             * ip_source = get_ip_source(request);
  char * issued_for = get_client_hostname(request), * id_token = NULL, * id_token_out = NULL, * refresh_token = NULL, * refresh_token_out = NULL, * access_token = NULL, * access_token_out = NULL, jti[OIDC_JTI_LENGTH] = {0};
  json_t * j_code, * j_body, * j_refresh_token, * j_client = NULL, * j_user, * j_amr, * j_claims_request = NULL;
  time_t now;
  
  if (client_id == NULL && request->auth_basic_user) {
    client_id = request->auth_basic_user;
  }
  if (code == NULL || client_id == NULL || redirect_uri == NULL) {
    response->status = 400;
  } else {
    if (j_assertion_client != NULL) {
      j_client = json_pack("{sisO}", "result", G_OK, "client", j_assertion_client);
    } else {
      j_client = check_client_valid(config, client_id, request->auth_basic_user, request->auth_basic_password, u_map_get(request->map_post_body, "client_id"), u_map_get(request->map_post_body, "client_secret"), redirect_uri, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE_FLAG, 0, ip_source);
    }
    if (check_result_value(j_client, G_OK)) {
      j_code = validate_authorization_code(config, code, client_id, redirect_uri, code_verifier);
      if (check_result_value(j_code, G_OK)) {
        if (json_string_length(json_object_get(json_object_get(j_code, "code"), "claims_request"))) {
          if ((j_claims_request = json_loads(json_string_value(json_object_get(json_object_get(j_code, "code"), "claims_request")), JSON_DECODE_ANY, NULL)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error loading JSON claims_request");
          }
        }
        j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, json_string_value(json_object_get(json_object_get(j_code, "code"), "username")));
        if (check_result_value(j_user, G_OK)) {
          time(&now);
          if ((refresh_token = generate_refresh_token()) != NULL) {
            j_refresh_token = serialize_refresh_token(config, 
                                                      GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, 
                                                      json_integer_value(json_object_get(json_object_get(j_code, "code"), "gpoc_id")), 
                                                      json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), 
                                                      client_id, 
                                                      json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), 
                                                      now, 
                                                      json_integer_value(json_object_get(json_object_get(j_code, "code"), "refresh-token-duration")), 
                                                      json_object_get(json_object_get(j_code, "code"), "refresh-token-rolling")==json_true(), 
                                                      json_object_get(j_claims_request, "userinfo"),
                                                      refresh_token, 
                                                      issued_for, 
                                                      u_map_get_case(request->map_header, "user-agent"));
            if (check_result_value(j_refresh_token, G_OK)) {
              if ((access_token = generate_access_token(config, 
                                                        json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), 
                                                        json_object_get(j_client, "client"), 
                                                        json_object_get(j_user, "user"), 
                                                        json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), 
                                                        json_object_get(j_claims_request, "userinfo"),
                                                        now,
                                                        jti)) != NULL) {
                if (serialize_access_token(config, 
                                           GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, 
                                           json_integer_value(json_object_get(j_refresh_token, "gpor_id")), 
                                           json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), 
                                           client_id, 
                                           json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")), 
                                           now, 
                                           issued_for, 
                                           u_map_get_case(request->map_header, "user-agent"),
                                           access_token,
                                           jti) == G_OK) {
                  if (json_object_get(json_object_get(j_code, "code"), "has-scope-openid") == json_true()) {
                    j_amr = get_amr_list_from_code(config, json_integer_value(json_object_get(json_object_get(j_code, "code"), "gpoc_id")));
                    if (check_result_value(j_amr, G_OK)) {
                      if ((id_token = generate_id_token(config, 
                                                        json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), 
                                                        json_object_get(j_user, "user"), 
                                                        json_object_get(j_client, "client"), 
                                                        now, 
                                                        config->glewlwyd_config->glewlwyd_callback_get_session_age(config->glewlwyd_config, 
                                                                                                                  request, 
                                                                                                                  json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list"))), 
                                                        json_string_value(json_object_get(json_object_get(j_code, "code"), "nonce")), 
                                                        json_object_get(j_amr, "amr"), 
                                                        access_token,
                                                        code,
                                                        json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")),
                                                        json_object_get(j_claims_request, "id_token"))) != NULL) {
                        if (serialize_id_token(config, 
                                               GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, 
                                               id_token, 
                                               json_string_value(json_object_get(json_object_get(j_code, "code"), "username")), 
                                               client_id, 
                                               now, 
                                               issued_for, 
                                               u_map_get_case(request->map_header, "user-agent")) == G_OK) {
                          if (disable_authorization_code(config, json_integer_value(json_object_get(json_object_get(j_code, "code"), "gpoc_id"))) == G_OK) {
                            if ((id_token_out = encrypt_token_if_required(config, id_token, json_object_get(j_client, "client"), GLEWLWYD_TOKEN_TYPE_ID_TOKEN)) != NULL && (access_token_out = encrypt_token_if_required(config, access_token, json_object_get(j_client, "client"), GLEWLWYD_TOKEN_TYPE_ACCESS_TOKEN)) != NULL && (refresh_token_out = encrypt_token_if_required(config, refresh_token, json_object_get(j_client, "client"), GLEWLWYD_TOKEN_TYPE_REFRESH_TOKEN)) != NULL) {
                              j_body = json_pack("{sssssssisIssss}",
                                                    "token_type",
                                                    "bearer",
                                                    "access_token",
                                                    access_token_out,
                                                    "refresh_token",
                                                    refresh_token_out,
                                                    "iat",
                                                    now,
                                                    "expires_in",
                                                    config->access_token_duration,
                                                    "scope",
                                                    json_string_value(json_object_get(json_object_get(j_code, "code"), "scope_list")),
                                                    "id_token",
                                                    id_token_out);
                              ulfius_set_json_body_response(response, 200, j_body);
                              json_decref(j_body);
                            } else {
                              y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error encrypt_token_if_required");
                              j_body = json_pack("{ss}", "error", "server_error");
                              ulfius_set_json_body_response(response, 500, j_body);
                              json_decref(j_body);
                            }
                            o_free(id_token_out);
                            o_free(access_token_out);
                            o_free(refresh_token_out);
                          } else {
                            y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error disable_authorization_code");
                            j_body = json_pack("{ss}", "error", "server_error");
                            ulfius_set_json_body_response(response, 500, j_body);
                            json_decref(j_body);
                          }
                        } else {
                          y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error serialize_id_token");
                          j_body = json_pack("{ss}", "error", "server_error");
                          ulfius_set_json_body_response(response, 500, j_body);
                          json_decref(j_body);
                        }
                      } else {
                        y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error serialize_access_token");
                        j_body = json_pack("{ss}", "error", "server_error");
                        ulfius_set_json_body_response(response, 500, j_body);
                        json_decref(j_body);
                      }
                      o_free(id_token);
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error generate_id_token");
                      j_body = json_pack("{ss}", "error", "server_error");
                      ulfius_set_json_body_response(response, 500, j_body);
                      json_decref(j_body);
                    }
                    json_decref(j_amr);
                  } else {
                    if (disable_authorization_code(config, json_integer_value(json_object_get(json_object_get(j_code, "code"), "gpoc_id"))) == G_OK) {
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
                    } else {
                      y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error disable_authorization_code");
                      j_body = json_pack("{ss}", "error", "server_error");
                      ulfius_set_json_body_response(response, 500, j_body);
                      json_decref(j_body);
                    }
                  }
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error get_amr_list_from_code");
                  j_body = json_pack("{ss}", "error", "server_error");
                  ulfius_set_json_body_response(response, 500, j_body);
                  json_decref(j_body);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error generate_access_token");
                j_body = json_pack("{ss}", "error", "server_error");
                ulfius_set_json_body_response(response, 500, j_body);
                json_decref(j_body);
              }
              o_free(access_token);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error serialize_refresh_token");
              j_body = json_pack("{ss}", "error", "server_error");
              ulfius_set_json_body_response(response, 500, j_body);
              json_decref(j_body);
            }
            json_decref(j_refresh_token);
            o_free(refresh_token);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error generate_refresh_token");
            j_body = json_pack("{ss}", "error", "server_error");
            ulfius_set_json_body_response(response, 500, j_body);
            json_decref(j_body);
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error glewlwyd_plugin_callback_get_user");
          j_body = json_pack("{ss}", "error", "server_error");
          ulfius_set_json_body_response(response, 500, j_body);
          json_decref(j_body);
        }
        json_decref(j_user);
      } else {
        y_log_message(Y_LOG_LEVEL_WARNING, "Security - Code invalid at IP Address %s", get_ip_source(request));
        j_body = json_pack("{ss}", "error", "invalid_code");
        ulfius_set_json_body_response(response, 403, j_body);
        json_decref(j_body);
      }
      json_decref(j_code);
      json_decref(j_claims_request);
    } else {
      j_body = json_pack("{ss}", "error", "unauthorized_client");
      ulfius_set_json_body_response(response, 403, j_body);
      json_decref(j_body);
    }
    json_decref(j_client);
  }
  o_free(issued_for);
  return U_CALLBACK_CONTINUE;
}

/**
 * The more simple authorization type
 * username and password are given in the POST parameters,
 * the access_token and refresh_token in a json object are returned
 */
static int check_auth_type_resource_owner_pwd_cred (const struct _u_request * request, struct _u_response * response, void * user_data, json_t * j_assertion_client) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  json_t * j_user, * j_client = NULL, * j_refresh_token, * j_body, * j_user_only, * j_client_for_sub = NULL, * j_element = NULL;
  int ret = G_OK, auth_type_allowed = 0;
  const char * username = u_map_get(request->map_post_body, "username"),
             * password = u_map_get(request->map_post_body, "password"),
             * scope = u_map_get(request->map_post_body, "scope"),
             * client_id = NULL,
             * ip_source = get_ip_source(request);
  char * issued_for = get_client_hostname(request),
       * refresh_token = NULL,
       * refresh_token_out = NULL,
       * access_token = NULL,
       * access_token_out = NULL,
         jti[OIDC_JTI_LENGTH] = {0};
  time_t now;
  size_t index = 0;
  
  if (scope == NULL || username == NULL || password == NULL || issued_for == NULL) {
    ret = G_ERROR_PARAM;
  } else if ((request->auth_basic_user != NULL && request->auth_basic_password != NULL) || j_assertion_client != NULL) {
    if (j_assertion_client != NULL) {
      j_client = json_pack("{sisO}", "result", G_OK, "client", j_assertion_client);
    } else {
      j_client = config->glewlwyd_config->glewlwyd_callback_check_client_valid(config->glewlwyd_config, request->auth_basic_user, request->auth_basic_password);
    }
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
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_resource_owner_pwd_cred - Error glewlwyd_callback_check_client_valid");
      ret = G_ERROR;
    }
    json_decref(j_client);
    j_client = NULL;
  }
  if (ret == G_OK) {
    j_user = config->glewlwyd_config->glewlwyd_callback_check_user_valid(config->glewlwyd_config, username, password, scope);
    if (check_result_value(j_user, G_OK)) {
      if (client_id != NULL) {
        if (j_assertion_client != NULL) {
          j_client = json_pack("{sisO}", "result", G_OK, "client", j_assertion_client);
        } else {
          j_client = config->glewlwyd_config->glewlwyd_plugin_callback_get_client(config->glewlwyd_config, client_id);
        }
        if (check_result_value(j_client, G_OK)) {
          j_client_for_sub = json_incref(json_object_get(j_client, "client"));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_resource_owner_pwd_cred - Error glewlwyd_plugin_callback_get_client");
          ret = G_ERROR;
        }
      }
      if (ret == G_OK) {
        time(&now);
        if ((refresh_token = generate_refresh_token()) != NULL) {
          j_refresh_token = serialize_refresh_token(config, 
                                                    GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, 
                                                    0, 
                                                    username, 
                                                    client_id, 
                                                    json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")), 
                                                    now, 
                                                    config->refresh_token_duration, 
                                                    config->refresh_token_rolling, 
                                                    NULL,
                                                    refresh_token, 
                                                    issued_for, 
                                                    u_map_get_case(request->map_header, "user-agent"));
          if (check_result_value(j_refresh_token, G_OK)) {
            j_user_only = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, username);
            if (check_result_value(j_user_only, G_OK)) {
              if ((access_token = generate_access_token(config, 
                                                        username, 
                                                        j_client_for_sub, 
                                                        json_object_get(j_user_only, "user"), 
                                                        json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")), 
                                                        NULL,
                                                        now,
                                                        jti)) != NULL) {
                if (serialize_access_token(config, 
                                           GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS, 
                                           json_integer_value(json_object_get(j_refresh_token, "gpgr_id")), 
                                           username, 
                                           client_id, 
                                           json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")), 
                                           now, 
                                           issued_for, 
                                           u_map_get_case(request->map_header, "user-agent"),
                                           access_token,
                                           jti) == G_OK) {
                  if ((access_token_out = encrypt_token_if_required(config, access_token, json_object_get(j_client, "client"), GLEWLWYD_TOKEN_TYPE_ACCESS_TOKEN)) != NULL && (refresh_token_out = encrypt_token_if_required(config, refresh_token, json_object_get(j_client, "client"), GLEWLWYD_TOKEN_TYPE_REFRESH_TOKEN)) != NULL) {
                    j_body = json_pack("{sssssssisIss}",
                                       "token_type",
                                       "bearer",
                                       "access_token",
                                       access_token_out,
                                       "refresh_token",
                                       refresh_token_out,
                                       "iat",
                                       now,
                                       "expires_in",
                                       config->access_token_duration,
                                       "scope",
                                       json_string_value(json_object_get(json_object_get(j_user, "user"), "scope_list")));
                    ulfius_set_json_body_response(response, 200, j_body);
                    json_decref(j_body);
                  } else {
                    y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_resource_owner_pwd_cred - Error encrypt_token_if_required");
                    j_body = json_pack("{ss}", "error", "server_error");
                    ulfius_set_json_body_response(response, 500, j_body);
                    json_decref(j_body);
                  }
                  o_free(access_token_out);
                  o_free(refresh_token_out);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_resource_owner_pwd_cred - Error serialize_access_token");
                  j_body = json_pack("{ss}", "error", "server_error");
                  ulfius_set_json_body_response(response, 500, j_body);
                  json_decref(j_body);
                }
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_resource_owner_pwd_cred - Error generate_access_token");
                j_body = json_pack("{ss}", "error", "server_error");
                ulfius_set_json_body_response(response, 500, j_body);
                json_decref(j_body);
              }
              o_free(access_token);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_resource_owner_pwd_cred - Error glewlwyd_plugin_callback_get_user");
              j_body = json_pack("{ss}", "error", "server_error");
              ulfius_set_json_body_response(response, 500, j_body);
              json_decref(j_body);
            }
            json_decref(j_user_only);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_resource_owner_pwd_cred - Error serialize_refresh_token");
            j_body = json_pack("{ss}", "error", "server_error");
            ulfius_set_json_body_response(response, 500, j_body);
            json_decref(j_body);
          }
          json_decref(j_refresh_token);
          o_free(refresh_token);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_resource_owner_pwd_cred - Error generate_refresh_token");
          j_body = json_pack("{ss}", "error", "server_error");
          ulfius_set_json_body_response(response, 500, j_body);
          json_decref(j_body);
        }
      }
      json_decref(j_client_for_sub);
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND) || check_result_value(j_user, G_ERROR_UNAUTHORIZED)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_auth_type_resource_owner_pwd_cred - Error user '%s'", username);
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Authorization invalid for username %s at IP Address %s", username, ip_source);
      response->status = 403;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_resource_owner_pwd_cred - glewlwyd_callback_check_user_valid");
      response->status = 403;
    }
    json_decref(j_user);
    json_decref(j_client);
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
static int check_auth_type_client_credentials_grant (const struct _u_request * request, struct _u_response * response, void * user_data, json_t * j_assertion_client) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  json_t * j_client, * j_element = NULL, * json_body;
  char ** scope_array, ** scope_allowed = NULL, * scope_joined, * access_token, * access_token_out, * issued_for = get_client_hostname(request), jti[OIDC_JTI_LENGTH] = {0};
  size_t index = 0;
  int i, i_scope_allowed = 0, auth_type_allowed = 0;
  time_t now;
  const char * ip_source = get_ip_source(request);

  if (issued_for == NULL) {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_client_credentials_grant  - Error get_client_hostname");
    response->status = 500;
  } else if (((request->auth_basic_user != NULL && request->auth_basic_password != NULL) || j_assertion_client != NULL) && o_strlen(u_map_get(request->map_post_body, "scope")) > 0) {
    if (j_assertion_client != NULL) {
      j_client = json_pack("{sisO}", "result", G_OK, "client", j_assertion_client);
    } else {
      j_client = config->glewlwyd_config->glewlwyd_callback_check_client_valid(config->glewlwyd_config, request->auth_basic_user, request->auth_basic_password);
    }
    if (check_result_value(j_client, G_OK) && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
      json_array_foreach(json_object_get(json_object_get(j_client, "client"), "authorization_type"), index, j_element) {
        if (0 == o_strcmp(json_string_value(j_element), "client_credentials")) {
          auth_type_allowed = 1;
        }
      }
      if (split_string(u_map_get(request->map_post_body, "scope"), " ", &scope_array) > 0) {
        for (i=0; scope_array[i]!=NULL; i++) {
          json_array_foreach(json_object_get(json_object_get(j_client, "client"), "scope"), index, j_element) {
            if (0 == o_strcmp(json_string_value(j_element), scope_array[i])) {
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
        } else if (!auth_type_allowed) {
          json_body = json_pack("{ss}", "error", "authorization_type_invalid");
          ulfius_set_json_body_response(response, 400, json_body);
          json_decref(json_body);
        } else {
          scope_joined = string_array_join((const char **)scope_allowed, " ");
          time(&now);
          if ((access_token = generate_client_access_token(config, json_object_get(j_client, "client"), scope_joined, now, jti)) != NULL) {
            if (serialize_access_token(config, 
                                       GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS, 
                                       0, 
                                       NULL, 
                                       request->auth_basic_user, 
                                       scope_joined, 
                                       now, 
                                       issued_for, 
                                       u_map_get_case(request->map_header, "user-agent"),
                                       access_token,
                                       jti) == G_OK) {
              if ((access_token_out = encrypt_token_if_required(config, access_token, json_object_get(j_client, "client"), GLEWLWYD_TOKEN_TYPE_ACCESS_TOKEN)) != NULL) {
                json_body = json_pack("{sssssIss}",
                                      "access_token", access_token_out,
                                      "token_type", "bearer",
                                      "expires_in", config->access_token_duration,
                                      "scope", scope_joined);
                ulfius_set_json_body_response(response, 200, json_body);
                json_decref(json_body);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_client_credentials_grant - Error encrypt_token_if_required");
                response->status = 500;
              }
              o_free(access_token_out);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_client_credentials_grant - Error serialize_access_token");
              response->status = 500;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_client_credentials_grant - Error generate_client_access_token");
            response->status = 500;
          }
          o_free(access_token);
          o_free(scope_joined);
          o_free(scope_allowed);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_client_credentials_grant - Error split_string");
        response->status = 500;
      }
      free_string_array(scope_array);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_auth_type_client_credentials_grant - Error client_id '%s' invalid", request->auth_basic_user);
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Authorization invalid for username %s at IP Address %s", request->auth_basic_user, ip_source);
      response->status = 403;
    }
    json_decref(j_client);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc check_auth_type_client_credentials_grant - Error invalid input parameters. client_id: '%s', scope: '%s', origin: %s", request->auth_basic_user, u_map_get(request->map_post_body, "scope"), ip_source);
    response->status = 403;
  }
  o_free(issued_for);
  return U_CALLBACK_CONTINUE;
}

/**
 * Get a new access_token from a valid refresh_token
 */
static int get_access_token_from_refresh (const struct _u_request * request, struct _u_response * response, void * user_data, json_t * j_assertion_client) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  const char * refresh_token = u_map_get(request->map_post_body, "refresh_token"), * ip_source = get_ip_source(request);
  json_t * j_refresh, * json_body, * j_client = NULL, * j_user, * j_client_for_sub = NULL, * j_claims_request = NULL;
  time_t now;
  char * access_token, * access_token_out, * scope_joined = NULL, * issued_for, jti[OIDC_JTI_LENGTH] = {0};
  int has_error = 0, has_issues = 0;

  if (refresh_token != NULL && o_strlen(refresh_token) == OIDC_REFRESH_TOKEN_LENGTH) {
    j_refresh = validate_refresh_token(config, refresh_token);
    if (check_result_value(j_refresh, G_OK)) {
      if (json_string_length(json_object_get(json_object_get(j_refresh, "token"), "claims_request"))) {
        if ((j_claims_request = json_loads(json_string_value(json_object_get(json_object_get(j_refresh, "token"), "claims_request")), JSON_DECODE_ANY, NULL)) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error loading JSON claims request");
        }
      }
      if (json_object_get(json_object_get(j_refresh, "token"), "client_id") != json_null()) {
        if (j_assertion_client != NULL) {
          j_client = json_pack("{sisO}", "result", G_OK, "client", j_assertion_client);
        } else {
          j_client = check_client_valid(config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), request->auth_basic_user, request->auth_basic_password, u_map_get(request->map_post_body, "client_id"), u_map_get(request->map_post_body, "client_secret"), NULL, GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN_FLAG, 0, ip_source);
        }
        if (!check_result_value(j_client, G_OK)) {
          has_issues = 1;
        } else if (request->auth_basic_user == NULL && request->auth_basic_password == NULL && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "oidc get_access_token_from_refresh - client '%s' is invalid or is not confidential", request->auth_basic_user, ip_source);
          has_issues = 1;
        }
        j_client_for_sub = json_incref(json_object_get(j_client, "client"));
      }
      time(&now);
      issued_for = get_client_hostname(request);
      scope_joined = join_json_string_array(json_object_get(json_object_get(j_refresh, "token"), "scope"), " ");
      if (scope_joined == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error join_json_string_array");
        has_error = 1;
      }
      if (update_refresh_token(config, json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "gpor_id")), (json_object_get(json_object_get(j_refresh, "token"), "rolling_expiration") == json_true())?json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "duration")):0, 0, now) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error update_refresh_token");
        has_error = 1;
      }
      if (!has_error && !has_issues) {
        j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "username")));
        if (check_result_value(j_user, G_OK)) {
          if ((access_token = generate_access_token(config, 
                                                    json_string_value(json_object_get(json_object_get(j_refresh, "token"), "username")), 
                                                    j_client_for_sub, 
                                                    json_object_get(j_user, "user"), 
                                                    scope_joined, 
                                                    j_claims_request,
                                                    now,
                                                    jti)) != NULL) {
            if (serialize_access_token(config, 
                                      GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN, 
                                      json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "gpor_id")), 
                                      json_string_value(json_object_get(json_object_get(j_refresh, "token"), "username")), 
                                      json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), 
                                      scope_joined, 
                                      now, 
                                      issued_for, 
                                      u_map_get_case(request->map_header, "user-agent"),
                                      access_token,
                                      jti) == G_OK) {
              if ((access_token_out = encrypt_token_if_required(config, access_token, json_object_get(j_client, "client"), GLEWLWYD_TOKEN_TYPE_ACCESS_TOKEN)) != NULL) {
                json_body = json_pack("{sssssIsssi}",
                                      "access_token", access_token_out,
                                      "token_type", "bearer",
                                      "expires_in", config->access_token_duration,
                                      "scope", scope_joined,
                                      "iat", now);
                ulfius_set_json_body_response(response, 200, json_body);
                json_decref(json_body);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error encrypt_token_if_required");
                response->status = 500;
              }
              o_free(access_token_out);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error serialize_access_token");
              response->status = 500;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error generate_client_access_token");
            response->status = 500;
          }
          o_free(access_token);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error glewlwyd_plugin_callback_get_user");
          response->status = 500;
        }
        json_decref(j_user);
      } else if (has_issues) {
        response->status = 400;
      } else {
        response->status = 500;
      }
      o_free(issued_for);
      json_decref(j_claims_request);
      json_decref(j_client);
    } else if (check_result_value(j_refresh, G_ERROR_NOT_FOUND)) {
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Token invalid at IP Address %s", get_ip_source(request));
      response->status = 400;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc get_access_token_from_refresh - Error validate_refresh_token");
      response->status = 500;
    }
    json_decref(j_refresh);
    o_free(scope_joined);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc get_access_token_from_refresh - Error token empty or missing, origin: %s", ip_source);
    response->status = 400;
  }
  json_decref(j_client_for_sub);
  return U_CALLBACK_CONTINUE;
}

/**
 * Invalidate a refresh token
 */
static int delete_refresh_token (const struct _u_request * request, struct _u_response * response, void * user_data, json_t * j_assertion_client) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  const char * refresh_token = u_map_get(request->map_post_body, "refresh_token"), * ip_source = get_ip_source(request);
  json_t * j_refresh, * j_client;
  time_t now;
  char * issued_for;
  int has_issues = 0;
  
  if (refresh_token != NULL && o_strlen(refresh_token)) {
    j_refresh = validate_refresh_token(config, refresh_token);
    if (check_result_value(j_refresh, G_OK)) {
      if (json_object_get(json_object_get(j_refresh, "token"), "client_id") != json_null()) {
        if (j_assertion_client != NULL) {
          j_client = json_pack("{sisO}", "result", G_OK, "client", j_assertion_client);
        } else {
          j_client = check_client_valid(config, json_string_value(json_object_get(json_object_get(j_refresh, "token"), "client_id")), request->auth_basic_user, request->auth_basic_password, u_map_get(request->map_post_body, "client_id"), u_map_get(request->map_post_body, "client_secret"), NULL, GLEWLWYD_AUTHORIZATION_TYPE_DELETE_TOKEN_FLAG, 0, ip_source);
        }
        if (!check_result_value(j_client, G_OK)) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "oidc delete_refresh_token - client '%s' is invalid, origin: %s", request->auth_basic_user, ip_source);
          has_issues = 1;
        } else if (request->auth_basic_user == NULL && request->auth_basic_password == NULL && json_object_get(json_object_get(j_client, "client"), "confidential") == json_true()) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "oidc delete_refresh_token - client '%s' is invalid or is not confidential, origin: %s", request->auth_basic_user, ip_source);
          has_issues = 1;
        }
        json_decref(j_client);
      }
      if (!has_issues) {
        time(&now);
        issued_for = get_client_hostname(request);
        if (update_refresh_token(config, json_integer_value(json_object_get(json_object_get(j_refresh, "token"), "gpor_id")), 0, 1, now) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc delete_refresh_token - Error update_refresh_token");
          response->status = 500;
        }
        o_free(issued_for);
      } else {
        response->status = 400;
      }
    } else if (check_result_value(j_refresh, G_ERROR_NOT_FOUND)) {
      y_log_message(Y_LOG_LEVEL_WARNING, "Security - Token invalid at IP Address %s", get_ip_source(request));
      response->status = 400;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc delete_refresh_token - Error validate_refresh_token");
      response->status = 500;
    }
    json_decref(j_refresh);
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "oidc delete_refresh_token - token missing or empty, origin: %s", ip_source);
    response->status = 400;
  }
  return U_CALLBACK_CONTINUE;
}

/**
 * verify that the http request is authorized based on the access token
 */
static int callback_check_userinfo(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  json_t * j_introspect;
  int ret = U_CALLBACK_UNAUTHORIZED;
  
  if (u_map_get_case(request->map_header, "Authorization") != NULL) {
    j_introspect = get_token_metadata(config, (u_map_get_case(request->map_header, "Authorization") + o_strlen(HEADER_PREFIX_BEARER)), "access_token", NULL);
    if (check_result_value(j_introspect, G_OK) && json_object_get(json_object_get(j_introspect, "token"), "active") == json_true()) {
      ret = callback_check_glewlwyd_oidc_access_token(request, response, (void*)config->oidc_resource_config);
    }
    json_decref(j_introspect);
  }
  return ret;
}

/**
 * verify that the http request is authorized based on the session or the access token
 */
static int callback_check_glewlwyd_session_or_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  json_t * j_session, * j_user, * j_introspect;
  int ret = U_CALLBACK_UNAUTHORIZED;
  char * username;
  
  if (u_map_get_case(request->map_header, "Authorization") != NULL) {
    j_introspect = get_token_metadata(config, (u_map_get_case(request->map_header, "Authorization") + o_strlen(HEADER_PREFIX_BEARER)), "access_token", NULL);
    if (check_result_value(j_introspect, G_OK) && json_object_get(json_object_get(j_introspect, "token"), "active") == json_true()) {
      ret = callback_check_glewlwyd_oidc_access_token(request, response, (void*)config->oidc_resource_config);
    }
    json_decref(j_introspect);
    if (ret == U_CALLBACK_CONTINUE) {
      username = get_username_from_sub(config, json_string_value(json_object_get((json_t *)response->shared_data, "sub")));
      if (username != NULL) {
        json_object_set_new((json_t *)response->shared_data, "username", json_string(username));
        o_free(username);
      } else {
        y_log_message(Y_LOG_LEVEL_DEBUG, "callback_check_glewlwyd_session_or_token - Error get_username_from_sub, origin: %s", get_ip_source(request));
        ret = U_CALLBACK_UNAUTHORIZED;
      }
    }
    return ret;
  } else {
    if (o_strlen(u_map_get(request->map_url, "impersonate"))) {
      j_session = config->glewlwyd_config->glewlwyd_callback_check_session_valid(config->glewlwyd_config, request, config->glewlwyd_config->glewlwyd_config->admin_scope);
      if (check_result_value(j_session, G_OK)) {
        j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, u_map_get(request->map_url, "impersonate"));
        if (check_result_value(j_user, G_OK)) {
          response->shared_data = json_pack("{ss}", "username", u_map_get(request->map_url, "impersonate"));
          ret = U_CALLBACK_CONTINUE;
        }
        json_decref(j_user);
      }
      json_decref(j_session);
    } else {
      j_session = config->glewlwyd_config->glewlwyd_callback_check_session_valid(config->glewlwyd_config, request, NULL);
      if (check_result_value(j_session, G_OK)) {
        response->shared_data = json_pack("{ss}", "username", json_string_value(json_object_get(json_object_get(json_object_get(j_session, "session"), "user"), "username")));
        ret = U_CALLBACK_CONTINUE;
      }
      json_decref(j_session);
    }
    return ret;
  }
}

/**
 * /auth callback
 */
static int callback_oidc_authorization(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  const char * response_type = NULL, * redirect_uri = NULL, * client_id = NULL, * nonce = NULL, * state_value = NULL, * ip_source = get_ip_source(request);
  int result = U_CALLBACK_CONTINUE;
  char * redirect_url, ** resp_type_array = NULL, * authorization_code = NULL, * authorization_code_out = NULL, * access_token = NULL, * id_token = NULL, * id_token_out = NULL, * expires_in_str = NULL, * iat_str = NULL, * query_parameters = NULL, * state = NULL, * str_request = NULL, * access_token_out = NULL, * session_state = NULL, jti[OIDC_JTI_LENGTH] = {0};
  json_t * j_auth_result = NULL, * j_request = NULL, * j_client = NULL;
  time_t now;
  int ret, implicit_flow = 1, auth_type = GLEWLWYD_AUTHORIZATION_TYPE_NULL_FLAG, check_request = 0;
  struct _u_map map_query, * map = get_map(request);
  int form_post = (0 == o_strcmp("form_post", u_map_get(map, "response_mode")));

  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");

  ret = G_OK;
  if (u_map_has_key(map, "state")) {
    state = get_state_param(u_map_get(map, "state"));
    state_value = u_map_get(map, "state");
  }

  if (u_map_has_key(map, "response_type")) {
    response_type = u_map_get(map, "response_type");
  }
  if (u_map_has_key(map, "redirect_uri")) {
    redirect_uri = u_map_get(map, "redirect_uri");
  }
  if (u_map_has_key(map, "client_id")) {
    client_id = u_map_get(map, "client_id");
  }
  if (u_map_has_key(map, "nonce")) {
    nonce = u_map_get(map, "nonce");
  }

  if (json_object_get(config->j_params, "request-parameter-allow") != json_false()) {
    if (o_strlen(u_map_get(map, "request")) && o_strlen(u_map_get(map, "request_uri"))) {
      // parameters request and request_uri at the same time is forbidden
      if (u_map_get(map, "redirect_uri") != NULL) {
        if (form_post) {
          build_form_post_error_response(map, response, "error", "invalid_request", NULL);
        } else {
          response->status = 302;
          redirect_url = msprintf("%s#error=invalid_request%s", u_map_get(map, "redirect_uri"), state);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
      } else {
        response->status = 403;
      }
      ret = G_ERROR_PARAM;
    } else if (ret == G_OK && o_strlen(u_map_get(map, "request_uri"))) {
      if ((str_request = get_request_from_uri(config, u_map_get(map, "request_uri"))) == NULL) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "callback_oidc_authorization - Error getting request from uri %s, origin: %s", u_map_get(map, "request_uri"), ip_source);
        if (u_map_get(map, "redirect_uri") != NULL) {
          if (form_post) {
            build_form_post_error_response(map, response, "error", "invalid_request", NULL);
          } else {
            response->status = 302;
            redirect_url = msprintf("%s#error=invalid_request%s", u_map_get(map, "redirect_uri"), state);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
          }
        } else {
          response->status = 403;
        }
        ret = G_ERROR_PARAM;
      } else {
        j_request = validate_jwt_auth_request(config, str_request, ip_source);
        check_request = 1;
      }
      o_free(str_request);
    } else if (ret == G_OK && o_strlen(u_map_get(map, "request"))) {
      j_request = validate_jwt_auth_request(config, u_map_get(map, "request"), ip_source);
      check_request = 1;
    }
  }
  
  if (ret == G_OK && check_request) {
    if (check_result_value(j_request, G_ERROR_UNAUTHORIZED) || check_result_value(j_request, G_ERROR_PARAM)) {
      response->status = 403;
      ret = G_ERROR_PARAM;
    } else if (!check_result_value(j_request, G_OK)) {
      response->status = 500;
      ret = G_ERROR;
    } else {
      if (!json_string_length(json_object_get(json_object_get(j_request, "request"), "client_id")) || (u_map_has_key(map, "client_id") && 0 != o_strcmp(json_string_value(json_object_get(json_object_get(j_request, "request"), "client_id")), u_map_get(map, "client_id")))) {
        // url parameter client_id can't differ from request parameter if set and must be present in request
        y_log_message(Y_LOG_LEVEL_DEBUG, "callback_oidc_authorization - client_id missing or invalid, origin: %s", ip_source);
        response->status = 403;
        ret = G_ERROR_PARAM;
      } else if (!json_string_length(json_object_get(json_object_get(j_request, "request"), "response_type")) || (u_map_has_key(map, "response_type") && 0 != o_strcmp(json_string_value(json_object_get(json_object_get(j_request, "request"), "response_type")), u_map_get(map, "response_type")))) {
        // url parameter response_type can't differ from request parameter if set and must be present in request
        y_log_message(Y_LOG_LEVEL_DEBUG, "callback_oidc_authorization - response_type missing or invalid, origin: %s", ip_source);
        response->status = 403;
        ret = G_ERROR_PARAM;
      } else if (!json_string_length(json_object_get(json_object_get(j_request, "request"), "redirect_uri"))) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "callback_oidc_authorization - redirect_uri missing, origin: %s", ip_source);
        // redirect_uri is mandatory
        response->status = 403;
        ret = G_ERROR_PARAM;
      } else {
        response_type = json_string_value(json_object_get(json_object_get(j_request, "request"), "response_type"));
        redirect_uri = json_string_value(json_object_get(json_object_get(j_request, "request"), "redirect_uri"));
        client_id = json_string_value(json_object_get(json_object_get(j_request, "request"), "client_id"));
        if (nonce == NULL) {
          nonce = json_string_value(json_object_get(json_object_get(j_request, "request"), "nonce"));
        }
        if (state == NULL) {
          state = get_state_param(json_string_value(json_object_get(json_object_get(j_request, "request"), "state")));
		  state_value = json_string_value(json_object_get(json_object_get(j_request, "request"), "state"));
        }
      }
    }
  }
  
  if (ret == G_OK) {
    if (!o_strlen(response_type)) {
      if (redirect_uri != NULL) {
        if (form_post) {
          build_form_post_error_response(map, response, "error", "invalid_request", NULL);
        } else {
          response->status = 302;
          redirect_url = msprintf("%s#error=invalid_request%s", redirect_uri, state);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
      } else {
        response->status = 403;
      }
      ret = G_ERROR_PARAM;
    } else if (split_string(response_type, " ", &resp_type_array)) {
      if (u_map_init(&map_query) == U_OK) {
        time(&now);
        
        if (state != NULL) {
          u_map_put(&map_query, "state", state_value);
        }
        
        if (!string_array_has_value((const char **)resp_type_array, "code") && 
            !string_array_has_value((const char **)resp_type_array, "token") &&
            !string_array_has_value((const char **)resp_type_array, "id_token") &&
            !string_array_has_value((const char **)resp_type_array, "none")) {
          if (form_post) {
            build_form_post_error_response(map, response, "error", "unsupported_response_type", NULL);
          } else {
            response->status = 302;
            redirect_url = msprintf("%s#error=unsupported_response_type%s", redirect_uri, state);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
          }
          ret = G_ERROR_PARAM;
        }

        if (ret == G_OK && string_array_size(resp_type_array) == 1 && string_array_has_value((const char **)resp_type_array, "token") && !config->allow_non_oidc) {
          if (form_post) {
            build_form_post_error_response(map, response, "error", "unsupported_response_type", NULL);
          } else {
            response->status = 302;
            redirect_url = msprintf("%s#error=unsupported_response_type%s", redirect_uri, state);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
          }
          ret = G_ERROR_PARAM;
        } else if (ret == G_OK && string_array_size(resp_type_array) == 1 && string_array_has_value((const char **)resp_type_array, "code")) {
          implicit_flow = 0;
        }

        if (ret == G_OK && string_array_has_value((const char **)resp_type_array, "code")) {
          auth_type |= GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE_FLAG;
        }

        if (ret == G_OK && string_array_has_value((const char **)resp_type_array, "token") && config->allow_non_oidc) {
          auth_type |= GLEWLWYD_AUTHORIZATION_TYPE_TOKEN_FLAG;
        }

        if (ret == G_OK && string_array_has_value((const char **)resp_type_array, "id_token")) {
          auth_type |= GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN_FLAG;
        }

        if (ret == G_OK && string_array_has_value((const char **)resp_type_array, "none")) {
          auth_type |= GLEWLWYD_AUTHORIZATION_TYPE_NONE_FLAG;
        }

        if (ret == G_OK) {
          j_auth_result = validate_endpoint_auth(request, response, user_data, auth_type, json_object_get(j_request, "request"), json_object_get(j_request, "client"));
          if (check_result_value(j_auth_result, G_ERROR_PARAM) || check_result_value(j_auth_result, G_ERROR_UNAUTHORIZED)) {
            ret = G_ERROR;
          } else if (!check_result_value(j_auth_result, G_OK)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_authorization - Error validate_endpoint_auth");
            ret = G_ERROR;
          }
        }
        
        if (ret == G_OK) {
          j_client = config->glewlwyd_config->glewlwyd_plugin_callback_get_client(config->glewlwyd_config, client_id);
          if (!check_result_value(j_client, G_OK)) {
            y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_authorization - Error glewlwyd_plugin_callback_get_client");
            ret = G_ERROR;
          }
        }

        if (json_object_get(config->j_params, "session-management-allowed") == json_true()) {
          session_state = generate_session_state(client_id, redirect_uri, json_string_value(json_object_get(json_object_get(json_object_get(j_auth_result, "session"), "user"), "username")));
          if (o_strlen(session_state)) {
            u_map_put(&map_query, "session_state", session_state);
          }
          o_free(session_state);
        }
    
        if (ret == G_OK && string_array_has_value((const char **)resp_type_array, "code")) {
          if (is_authorization_type_enabled((struct _oidc_config *)user_data, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE) && redirect_uri != NULL) {
            // Generates authorization code
            if ((authorization_code = generate_authorization_code(config,
                                                                  json_string_value(json_object_get(json_object_get(json_object_get(j_auth_result, "session"), "user"), "username")), 
                                                                  client_id, 
                                                                  json_string_value(json_object_get(json_object_get(j_auth_result, "session"), "scope_filtered")), 
                                                                  redirect_uri, 
                                                                  json_string_value(json_object_get(j_auth_result, "issued_for")),
                                                                  u_map_get_case(request->map_header, "user-agent"), 
                                                                  nonce, 
                                                                  json_object_get(json_object_get(j_auth_result, "session"), "amr"),
                                                                  json_object_get(j_auth_result, "claims"),
                                                                  auth_type,
                                                                  json_string_value(json_object_get(j_auth_result, "code_challenge")))) == NULL) {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_auth_code_grant - Error generate_authorization_code");
              if (form_post) {
                build_form_post_error_response(map, response, "error", "server_error", NULL);
              } else {
                response->status = 302;
                redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
              }
              ret = G_ERROR;
            } else {
              if ((authorization_code_out = encrypt_token_if_required(config, authorization_code, json_object_get(j_client, "client"), GLEWLWYD_TOKEN_TYPE_CODE)) != NULL) {
                u_map_put(&map_query, "code", authorization_code_out);
              } else {
                if (form_post) {
                  build_form_post_error_response(map, response, "error", "server_error", NULL);
                } else {
                  response->status = 302;
                  redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
                  ulfius_add_header_to_response(response, "Location", redirect_url);
                  o_free(redirect_url);
                }
                ret = G_ERROR;
              }
              o_free(authorization_code_out);
            }
          } else {
            if (redirect_uri != NULL) {
              if (form_post) {
                build_form_post_error_response(map, response, "error", "unsupported_response_type", NULL);
              } else {
                response->status = 302;
                redirect_url = msprintf("%s#error=unsupported_response_type%s", redirect_uri, state);
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
              }
            } else {
              response->status = 403;
            }
            ret = G_ERROR_PARAM;
          }
        }

        if (ret == G_OK && string_array_has_value((const char **)resp_type_array, "token")) {
          if (is_authorization_type_enabled((struct _oidc_config *)user_data, GLEWLWYD_AUTHORIZATION_TYPE_TOKEN) && redirect_uri != NULL) {
            if ((access_token = generate_access_token(config, 
                                                      json_string_value(json_object_get(json_object_get(json_object_get(j_auth_result, "session"), "user"), "username")), 
                                                      json_object_get(j_client, "client"),
                                                      json_object_get(json_object_get(j_auth_result, "session"), "user"), 
                                                      json_string_value(json_object_get(json_object_get(j_auth_result, "session"), "scope_filtered")), 
                                                      json_object_get(json_object_get(j_auth_result, "claims"), "userinfo"),
                                                      now,
                                                      jti)) != NULL) {
              if (serialize_access_token(config, 
                                         auth_type, 
                                         0, 
                                         json_string_value(json_object_get(json_object_get(json_object_get(j_auth_result, "session"), "user"), "username")), 
                                         client_id, 
                                         json_string_value(json_object_get(json_object_get(j_auth_result, "session"), "scope_filtered")), 
                                         now, 
                                         json_string_value(json_object_get(j_auth_result, "issued_for")),
                                         u_map_get_case(request->map_header, "user-agent"),
                                         access_token,
                                         jti) != G_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_implicit_grant - Error serialize_access_token");
                if (form_post) {
                  build_form_post_error_response(map, response, "error", "server_error", NULL);
                } else {
                  response->status = 302;
                  redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
                  ulfius_add_header_to_response(response, "Location", redirect_url);
                  o_free(redirect_url);
                }
                ret = G_ERROR;
              } else {
                if ((access_token_out = encrypt_token_if_required(config, access_token, json_object_get(j_client, "client"), GLEWLWYD_TOKEN_TYPE_ACCESS_TOKEN)) != NULL) {
                  expires_in_str = msprintf("%" JSON_INTEGER_FORMAT, config->access_token_duration);
                  iat_str = msprintf("%ld", now);
                  u_map_put(&map_query, "access_token", access_token_out);
                  u_map_put(&map_query, "token_type", "bearer");
                  u_map_put(&map_query, "expires_in", expires_in_str);
                  u_map_put(&map_query, "iat", iat_str);
                  u_map_put(&map_query, "scope", json_string_value(json_object_get(json_object_get(j_auth_result, "session"), "scope_filtered")));
                  o_free(expires_in_str);
                  o_free(iat_str);
                } else {
                  response->status = 302;
                  redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
                  ulfius_add_header_to_response(response, "Location", redirect_url);
                  o_free(redirect_url);
                  ret = G_ERROR;
                }
                o_free(access_token_out);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_implicit_grant - Error generate_access_token");
              if (form_post) {
                build_form_post_error_response(map, response, "error", "server_error", NULL);
              } else {
                response->status = 302;
                redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
              }
              ret = G_ERROR;
            }
          } else {
            if (redirect_uri != NULL) {
              if (form_post) {
                build_form_post_error_response(map, response, "error", "unsupported_response_type", NULL);
              } else {
                response->status = 302;
                redirect_url = msprintf("%s#error=unsupported_response_type%s", redirect_uri, state);
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
              }
            } else {
              response->status = 403;
            }
            ret = G_ERROR_PARAM;
          }
        }

        if (ret == G_OK && string_array_has_value((const char **)resp_type_array, "id_token")) {
          if (is_authorization_type_enabled((struct _oidc_config *)user_data, GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN) && redirect_uri != NULL) {
            if ((id_token = generate_id_token(config, 
                                              json_string_value(json_object_get(json_object_get(json_object_get(j_auth_result, "session"), "user"), "username")), 
                                              json_object_get(json_object_get(j_auth_result, "session"), "user"), 
                                              json_object_get(j_auth_result, "client"), 
                                              now, 
                                              config->glewlwyd_config->glewlwyd_callback_get_session_age(config->glewlwyd_config, 
                                                                                                         request, 
                                                                                                         json_string_value(json_object_get(json_object_get(j_auth_result, "session"), "scope_filtered"))), 
                                              nonce, 
                                              json_object_get(json_object_get(j_auth_result, "session"), "amr"),
                                              access_token,
                                              authorization_code,
                                              json_string_value(json_object_get(json_object_get(j_auth_result, "session"), "scope_filtered")),
                                              json_object_get(json_object_get(j_auth_result, "claims"), "id_token"))) != NULL) {
              if (serialize_id_token(config, 
                                     GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE, 
                                     id_token, 
                                     json_string_value(json_object_get(json_object_get(json_object_get(j_auth_result, "session"), "user"), "username")), 
                                     client_id, 
                                     now, 
                                     json_string_value(json_object_get(j_auth_result, "issued_for")), 
                                     u_map_get_case(request->map_header, "user-agent")) != G_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error serialize_id_token");
                if (form_post) {
                  build_form_post_error_response(map, response, "error", "server_error", NULL);
                } else {
                  response->status = 302;
                  redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
                  ulfius_add_header_to_response(response, "Location", redirect_url);
                  o_free(redirect_url);
                }
                ret = G_ERROR;
              } else {
                if ((id_token_out = encrypt_token_if_required(config, id_token, json_object_get(j_client, "client"), GLEWLWYD_TOKEN_TYPE_ID_TOKEN)) != NULL) {
                  u_map_put(&map_query, "id_token", id_token_out);
                } else {
                  response->status = 302;
                  redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
                  ulfius_add_header_to_response(response, "Location", redirect_url);
                  o_free(redirect_url);
                  ret = G_ERROR;
                }
                o_free(id_token_out);
              }
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "oidc check_auth_type_access_token_request - Error generate_id_token");
              if (form_post) {
                build_form_post_error_response(map, response, "error", "server_error", NULL);
              } else {
                response->status = 302;
                redirect_url = msprintf("%s%serror=server_error", redirect_uri, (o_strchr(redirect_uri, '?')!=NULL?"&":"?"));
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
              }
              ret = G_ERROR;
            }
          } else {
            if (redirect_uri != NULL) {
              if (form_post) {
                build_form_post_error_response(map, response, "error", "unsupported_response_type", NULL);
              } else {
                response->status = 302;
                redirect_url = msprintf("%s#error=unsupported_response_type%s", redirect_uri, state);
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
              }
            } else {
              response->status = 403;
            }
            ret = G_ERROR_PARAM;
          }
        }

        if (ret == G_OK && string_array_has_value((const char **)resp_type_array, "none")) {
          if (!is_authorization_type_enabled((struct _oidc_config *)user_data, GLEWLWYD_AUTHORIZATION_TYPE_NONE)) {
            if (redirect_uri != NULL) {
              if (form_post) {
                build_form_post_error_response(map, response, "error", "unsupported_response_type", NULL);
              } else {
                response->status = 302;
                redirect_url = msprintf("%s#error=unsupported_response_type%s", redirect_uri, state);
                ulfius_add_header_to_response(response, "Location", redirect_url);
                o_free(redirect_url);
              }
            } else {
              response->status = 403;
            }
            ret = G_ERROR_PARAM;
          }
        }

        if (ret == G_OK) {
          if (form_post) {
            build_form_post_response(redirect_uri, &map_query, response);
          } else {
            response->status = 302;
            query_parameters = generate_query_parameters(&map_query);
            redirect_url = msprintf("%s%c%s", redirect_uri, get_url_separator(redirect_uri, implicit_flow), query_parameters);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
            o_free(query_parameters);
          }
        }
        o_free(authorization_code);
        o_free(access_token);
        o_free(id_token);
        u_map_clean(&map_query);
        json_decref(j_auth_result);
        json_decref(j_client);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_authorization - Error u_map_init");
        if (redirect_uri != NULL) {
          if (form_post) {
            build_form_post_error_response(map, response, "error", "server_error", NULL);
          } else {
            response->status = 302;
            redirect_url = msprintf("%s#error=server_error%s", redirect_uri, state);
            ulfius_add_header_to_response(response, "Location", redirect_url);
            o_free(redirect_url);
          }
        } else {
          response->status = 403;
        }
      }
      free_string_array(resp_type_array);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_authorization - Error split_string");
      if (redirect_uri != NULL) {
        if (form_post) {
          build_form_post_error_response(map, response, "error", "server_error", NULL);
        } else {
          response->status = 302;
          redirect_url = msprintf("%s#error=server_error%s", redirect_uri, state);
          ulfius_add_header_to_response(response, "Location", redirect_url);
          o_free(redirect_url);
        }
      } else {
        response->status = 403;
      }
    }
  }
  o_free(state);
  json_decref(j_request);

  return result;
}

/**
 * /token callback
 */
static int callback_oidc_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  const char * grant_type = u_map_get(request->map_post_body, "grant_type"), * ip_source = get_ip_source(request);
  int result = U_CALLBACK_CONTINUE;
  json_t * j_assertion = NULL, * j_assertion_client = NULL;

  if (o_strlen(u_map_get(request->map_post_body, "client_assertion")) && 0 == o_strcmp(GLEWLWYD_AUTH_TOKEN_ASSERTION_TYPE, u_map_get(request->map_post_body, "client_assertion_type"))) {
    if (json_object_get(config->j_params, "request-parameter-allow") == json_true()) {
      j_assertion = validate_jwt_assertion_request(config, u_map_get(request->map_post_body, "client_assertion"), ip_source);
      if (check_result_value(j_assertion, G_ERROR_UNAUTHORIZED) || check_result_value(j_assertion, G_ERROR_PARAM)) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "callback_oidc_token - Error validating client_assertion");
        result = U_CALLBACK_UNAUTHORIZED;
      } else if (!check_result_value(j_assertion, G_OK)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_token - Error validate_jwt_assertion_request");
        result = U_CALLBACK_ERROR;
      } else {
        j_assertion_client = json_object_get(j_assertion, "client");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "callback_oidc_token - unauthorized request parameter");
      result = U_CALLBACK_UNAUTHORIZED;
    }
  }
  
  if (result == U_CALLBACK_CONTINUE) {
    if (0 == o_strcmp("authorization_code", grant_type)) {
      if (is_authorization_type_enabled(config, GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE)) {
        result = check_auth_type_access_token_request(request, response, user_data, j_assertion_client);
      } else {
        response->status = 403;
      }
    } else if (0 == o_strcmp("password", grant_type)) {
      if (is_authorization_type_enabled(config, GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS) && config->allow_non_oidc) {
        result = check_auth_type_resource_owner_pwd_cred(request, response, user_data, j_assertion_client);
      } else {
        response->status = 403;
      }
    } else if (0 == o_strcmp("client_credentials", grant_type)) {
      if (is_authorization_type_enabled(config, GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS) && config->allow_non_oidc) {
        result = check_auth_type_client_credentials_grant(request, response, user_data, j_assertion_client);
      } else {
        response->status = 403;
      }
    } else if (0 == o_strcmp("refresh_token", grant_type)) {
      if (is_authorization_type_enabled(config, GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN)) {
        result = get_access_token_from_refresh(request, response, user_data, j_assertion_client);
      } else {
        response->status = 403;
      }
    } else if (0 == o_strcmp("delete_token", grant_type)) {
      result = delete_refresh_token(request, response, user_data, j_assertion_client);
    } else {
      y_log_message(Y_LOG_LEVEL_DEBUG, "oidc callback_oidc_token - Unknown grant_type '%s', origin: %s", grant_type, get_ip_source(request));
      response->status = 400;
    }
  } else if (result == U_CALLBACK_UNAUTHORIZED) {
    result = U_CALLBACK_CONTINUE;
    response->status = 403;
  }
  
  json_decref(j_assertion);

  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");

  return result;
}

/**
 * /userinfo callback
 */
static int callback_oidc_get_userinfo(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  char * username = get_username_from_sub(config, json_string_value(json_object_get((json_t *)response->shared_data, "sub"))), * token = NULL, * token_out = NULL;
  json_t * j_user, * j_userinfo, * j_client = config->glewlwyd_config->glewlwyd_plugin_callback_get_client(config->glewlwyd_config, json_string_value(json_object_get((json_t *)response->shared_data, "aud")));
  jwt_t * jwt = NULL;
  jwk_t * jwk = NULL;
  const char * sign_kid = json_string_value(json_object_get(config->j_params, "client-sign_kid-parameter"));

  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");

  if (username != NULL) {
    j_user = config->glewlwyd_config->glewlwyd_plugin_callback_get_user(config->glewlwyd_config, username);
    if (check_result_value(j_user, G_OK)) {
      j_userinfo = get_userinfo(config, json_string_value(json_object_get((json_t *)response->shared_data, "sub")), json_object_get(j_user, "user"), json_object_get((json_t *)response->shared_data, "claims"), json_string_value(json_object_get((json_t *)response->shared_data, "scope")));
      if (j_userinfo != NULL) {
        if (0 == o_strcmp("jwt", u_map_get(request->map_url, "format")) || 0 == o_strcmp("jwt", u_map_get(request->map_post_body, "format")) || 0 == o_strcasecmp("application/jwt", u_map_get(request->map_header, "Accept"))) {
          if ((jwt = r_jwt_copy(config->jwt_sign)) != NULL) {
            json_object_set(j_userinfo, "iss", json_object_get(config->j_params, "iss"));
            if (r_jwt_set_full_claims_json_t(jwt, j_userinfo) == RHN_OK) {
              if (check_result_value(j_client, G_OK)) {
                if (json_string_length(json_object_get(json_object_get(j_client, "client"), sign_kid))) {
                  jwk = r_jwks_get_by_kid(config->jwt_sign->jwks_privkey_sign, json_string_value(json_object_get(json_object_get(j_client, "client"), sign_kid)));
                } else {
                  jwk = r_jwk_copy(config->jwk_sign_default);
                }
              } else {
                jwk = r_jwk_copy(config->jwk_sign_default);
              }
              token = r_jwt_serialize_signed(jwt, jwk, 0);
              r_jwk_free(jwk);
              if (token != NULL) {
                if ((token_out = encrypt_token_if_required(config, token, json_object_get(j_client, "client"), GLEWLWYD_TOKEN_TYPE_USERINFO)) != NULL) {
                  ulfius_set_string_body_response(response, 200, token_out);
                  u_map_put(response->map_header, "Content-Type", "application/jwt");
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_get_userinfo oidc - Error encrypt_token_if_required");
                  response->status = 500;
                }
                o_free(token_out);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_get_userinfo oidc - Error r_jwt_serialize_signed");
                response->status = 500;
              }
              o_free(token);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_get_userinfo oidc - Error r_jwt_set_full_claims_json_t");
              response->status = 500;
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_get_userinfo oidc - Error r_jwt_copy");
            response->status = 500;
          }
          r_jwt_free(jwt);
        } else {
          ulfius_set_json_body_response(response, 200, j_userinfo);
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_get_userinfo oidc - Error get_userinfo");
        response->status = 500;
      }
      json_decref(j_userinfo);
    } else if (check_result_value(j_user, G_ERROR_NOT_FOUND)) {
      response->status = 404;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_get_userinfo oidc - Error glewlwyd_plugin_callback_get_user_profile");
      response->status = 500;
    }
    json_decref(j_user);
  } else {
    response->status = 404;
  }
  o_free(username);
  json_decref(j_client);
  return U_CALLBACK_CONTINUE;
}

/**
 * GET /token callback
 */
static int callback_oidc_refresh_token_list_get(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
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
    sort = msprintf("gpor_%s%s", u_map_get(request->map_url, "sort"), (u_map_get_case(request->map_url, "desc")!=NULL?" DESC":" ASC"));
  }
  j_refresh_list = refresh_token_list_get(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), u_map_get(request->map_url, "pattern"), offset, limit, sort);
  if (check_result_value(j_refresh_list, G_OK)) {
    ulfius_set_json_body_response(response, 200, json_object_get(j_refresh_list, "refresh_token"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_refresh_token_list_get - Error refresh_token_list_get");
    response->status = 500;
  }
  o_free(sort);
  json_decref(j_refresh_list);
  return U_CALLBACK_CONTINUE;
}

/**
 * DELETE /token callback
 */
static int callback_oidc_disable_refresh_token(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  int res;

  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");

  if ((res = refresh_token_disable(config, json_string_value(json_object_get((json_t *)response->shared_data, "username")), u_map_get(request->map_url, "token_hash"), get_ip_source(request))) == G_ERROR_NOT_FOUND) {
    response->status = 404;
  } else if (res == G_ERROR_PARAM) {
    response->status = 400;
  } else if (res != G_OK) {
    y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_disable_refresh_token - Error refresh_token_disable");
    response->status = 500;
  }
  return U_CALLBACK_CONTINUE;
}

/**
 * cleanup callback
 */
static int callback_oidc_clean(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  UNUSED(user_data);
  if (response->shared_data != NULL) {
    json_decref((json_t *)response->shared_data);
  }
  return U_CALLBACK_COMPLETE;
}

/**
 * /.well-known/openid-configuration callback
 */
static int callback_oidc_discovery(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);

  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");

  u_map_put(response->map_header, ULFIUS_HTTP_HEADER_CONTENT, ULFIUS_HTTP_ENCODING_JSON);
  ulfius_set_string_body_response(response, 200, ((struct _oidc_config *)user_data)->discovery_str);
  return U_CALLBACK_CONTINUE;
}

/**
 * /jwks allback
 */
static int callback_oidc_get_jwks(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  struct _oidc_config * config = (struct _oidc_config *)user_data;

  u_map_put(response->map_header, "Cache-Control", "no-store");
  u_map_put(response->map_header, "Pragma", "no-cache");
  u_map_put(response->map_header, "Referrer-Policy", "no-referrer");
  
  if (config->jwks_str != NULL) {
    u_map_put(response->map_header, ULFIUS_HTTP_HEADER_CONTENT, ULFIUS_HTTP_ENCODING_JSON);
    ulfius_set_string_body_response(response, 200, config->jwks_str);
  } else {
    ulfius_set_string_body_response(response, 403, "JWKS unavailable");
  }
  return U_CALLBACK_CONTINUE;
}

/**
 * OP Iframe to validate session_state
 */
static int callback_oidc_check_session_iframe(const struct _u_request * request, struct _u_response * response, void * user_data) {
  UNUSED(request);
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  u_map_put(response->map_header, "Content-Type", "text/html; charset=utf-8");
  ulfius_set_string_body_response(response, 200, config->check_session_iframe);
  return U_CALLBACK_CONTINUE;
}

/**
 * Redirects the user to an end session prompt
 */
static int callback_oidc_end_session(const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _oidc_config * config = (struct _oidc_config *)user_data;
  struct _u_map map;
  char * logout_url, * post_logout_redirect_uri = NULL, * state;
  json_t * j_metadata, * j_client;
  
  if (u_map_get(request->map_url, "post_logout_redirect_uri") != NULL) {
    j_metadata = get_token_metadata(config, u_map_get(request->map_url, "id_token_hint"), "id_token", NULL);
    if (check_result_value(j_metadata, G_OK) && json_object_get(json_object_get(j_metadata, "token"), "active") == json_true()) {
      j_client = config->glewlwyd_config->glewlwyd_plugin_callback_get_client(config->glewlwyd_config, json_string_value(json_object_get(json_object_get(j_metadata, "token"), "client_id")));
      if (check_result_value(j_client, G_OK)) {
        if (json_array_has_string(json_object_get(json_object_get(j_client, "client"), "post_logout_redirect_uris"), u_map_get(request->map_url, "post_logout_redirect_uri"))) {
          if (u_map_get(request->map_url, "state") != NULL) {
            if (o_strlen(u_map_get(request->map_url, "state"))) {
              state = msprintf("state=%s", u_map_get(request->map_url, "state"));
            } else {
              state = o_strdup("");
            }
            if (o_strrchr(u_map_get(request->map_url, "post_logout_redirect_uri"), '?') != NULL || o_strrchr(u_map_get(request->map_url, "post_logout_redirect_uri"), '#') != NULL) {
              post_logout_redirect_uri = msprintf("%s&%s", u_map_get(request->map_url, "post_logout_redirect_uri"), state);
            } else {
              post_logout_redirect_uri = msprintf("%s?%s", u_map_get(request->map_url, "post_logout_redirect_uri"), state);
            }
            o_free(state);
          } else {
            post_logout_redirect_uri = o_strdup(u_map_get(request->map_url, "post_logout_redirect_uri"));
          }
        } {
          y_log_message(Y_LOG_LEVEL_DEBUG, "callback_oidc_end_session - Invalid post_logout_redirect_uris");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_end_session - Error getting client_id %s", json_string_value(json_object_get(json_object_get(j_metadata, "token"), "client_id")));
      }
      json_decref(j_client);
    } {
      y_log_message(Y_LOG_LEVEL_DEBUG, "callback_oidc_end_session - Invalid id_token");
    }
    json_decref(j_metadata);
  }
  if (u_map_has_key(request->map_url, "id_token_hint")) {
    if (revoke_id_token(config, u_map_get(request->map_url, "id_token_hint")) != G_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "callback_oidc_end_session - Error revoke_id_token");
    }
  }
  u_map_init(&map);
  u_map_put(&map, "prompt", "end_session");
  logout_url = config->glewlwyd_config->glewlwyd_callback_get_login_url(config->glewlwyd_config, NULL, NULL, post_logout_redirect_uri, &map);
  response->status = 302;
  ulfius_add_header_to_response(response, "Location", logout_url);
  u_map_clean(&map);
  o_free(logout_url);
  o_free(post_logout_redirect_uri);
  return U_CALLBACK_CONTINUE;
}

/**
 * verify the private key and public key are valid to build and verify jwts
 */
static int jwt_autocheck(struct _oidc_config * config) {
  time_t now;
  char * token, jti[OIDC_JTI_LENGTH] = {0};
  jwt_t * jwt = NULL;
  int ret;
  
  time(&now);
  token = generate_access_token(config, GLEWLWYD_CHECK_JWT_USERNAME, NULL, NULL, GLEWLWYD_CHECK_JWT_SCOPE, NULL, now, jti);
  if (token != NULL) {
    jwt = r_jwt_copy(config->oidc_resource_config->jwt);
    if (r_jwt_parse(jwt, token, 0) == RHN_OK && r_jwt_verify_signature(jwt, config->oidc_resource_config->jwk_verify_default, 0) == RHN_OK) {
      ret = RHN_OK;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "oidc jwt_autocheck - oidc - Error verifying signature");
      ret = G_ERROR_PARAM;
    }
    r_jwt_free(jwt);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc jwt_autocheck - oidc - Error generate_access_token");
    ret = G_ERROR;
  }
  o_free(token);
  return ret;
}

json_t * plugin_module_load(struct config_plugin * config) {
  UNUSED(config);
  return json_pack("{si ss ss ss s{ s{sssos[sss]} s{sssos[sss]} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ssso} s{ss so s{ssso} s{ssso} }}}",
                   "result",
                   G_OK,
                   
                   "name",
                   "oidc",
                   
                   "display_name",
                   "Glewlwyd OpenID Connect plugin",
                   
                   "description",
                   "Plugin for Glewlwyd OpenID Connect workflow",
                   
                   "parameters",
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
                       
                     "code-token-duration",
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
  UNUSED(config);
  return G_OK;
}

json_t * plugin_module_init(struct config_plugin * config, const char * name, json_t * j_parameters, void ** cls) {
  jwa_alg alg = R_JWA_ALG_UNKNOWN;
  pthread_mutexattr_t mutexattr;
  json_t * j_return = NULL, * j_result = NULL, * j_element = NULL;
  size_t index = 0;
  struct _oidc_config * p_config = NULL;
  jwk_t * jwk = NULL, * jwk_pub = NULL;
  jwks_t * jwks_privkey = NULL, * jwks_pubkey = NULL, * jwks_published = NULL;
  const char * str_alg;
  int key_type;
  const unsigned char * key;
  size_t key_len;
  
  y_log_message(Y_LOG_LEVEL_INFO, "Init plugin Glewlwyd OpenID Connect '%s'", name);
  *cls = o_malloc(sizeof(struct _oidc_config));
  if (*cls != NULL) {
    p_config = *cls;
    
    do {
      pthread_mutexattr_init ( &mutexattr );
      pthread_mutexattr_settype( &mutexattr, PTHREAD_MUTEX_RECURSIVE );
      if (pthread_mutex_init(&((struct _oidc_config *)*cls)->insert_lock, &mutexattr) != 0) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc plugin_module_init - Error initializing insert_lock");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }
      pthread_mutexattr_destroy(&mutexattr);
      
      // Initialize empty vaiables
      p_config->name = name;
      p_config->jwt_sign = NULL;
      p_config->jwk_sign_default = NULL;
      p_config->jwt_key_size = 0;
      p_config->x5u_flags = 0;
      p_config->glewlwyd_config = config;
      p_config->j_params = json_incref(j_parameters);
      json_object_set_new(p_config->j_params, "name", json_string(name));
      p_config->oidc_resource_config = NULL;
      p_config->introspect_revoke_resource_config = NULL;
      p_config->client_register_resource_config = NULL;
      p_config->discovery_str = NULL;
      p_config->jwks_str = NULL;
      p_config->check_session_iframe = NULL;
      
      j_result = check_parameters(((struct _oidc_config *)*cls)->j_params);

      if (check_result_value(j_result, G_ERROR_PARAM)) {
        j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_result, "error"));
        break;
      } else if (!check_result_value(j_result, G_OK)) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error check_parameters");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }
      
      if ((p_config->oidc_resource_config = o_malloc(sizeof(struct _oidc_resource_config))) == NULL) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc plugin_module_init - Error initializing oidc_resource_config");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }
      
      p_config->oidc_resource_config->method = G_METHOD_HEADER;
      p_config->oidc_resource_config->oauth_scope = NULL;
      p_config->oidc_resource_config->jwt = NULL;
      p_config->oidc_resource_config->jwk_verify_default = NULL;
      p_config->oidc_resource_config->realm = NULL;
      p_config->oidc_resource_config->accept_access_token = 1;
      p_config->oidc_resource_config->accept_client_token = 0;
      
      // Set config variables with conig parameters
      p_config->x5u_flags = R_FLAG_FOLLOW_REDIRECT|(json_object_get(p_config->j_params, "request-uri-allow-https-non-secure")==json_true()?R_FLAG_IGNORE_SERVER_CERTIFICATE:0);

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
      if (json_object_get(p_config->j_params, "allow-non-oidc") != NULL) {
        p_config->allow_non_oidc = json_object_get(p_config->j_params, "allow-non-oidc")==json_true()?1:0;
      } else {
        p_config->allow_non_oidc = 0;
      }
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_AUTHORIZATION_CODE] = json_object_get(p_config->j_params, "auth-type-code-enabled")==json_true()?1:0;
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_TOKEN] = json_object_get(p_config->j_params, "auth-type-token-enabled")==json_true()?1:0;
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_ID_TOKEN] = 1; // Force allow this auth type, otherwise use the other plugin
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_NONE] = json_object_get(p_config->j_params, "auth-type-none-enabled")==json_true()?1:0;
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_RESOURCE_OWNER_PASSWORD_CREDENTIALS] = json_object_get(p_config->j_params, "auth-type-password-enabled")==json_true()?1:0;
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_CLIENT_CREDENTIALS] = json_object_get(p_config->j_params, "auth-type-client-enabled")==json_true()?1:0;
      p_config->auth_type_enabled[GLEWLWYD_AUTHORIZATION_TYPE_REFRESH_TOKEN] = json_object_get(p_config->j_params, "auth-type-refresh-enabled")==json_true()?1:0;
      p_config->subject_type = 0==o_strcmp("pairwise", json_string_value(json_object_get(p_config->j_params, "subject-type")))?GLEWLWYD_OIDC_SUBJECT_TYPE_PAIRWISE:GLEWLWYD_OIDC_SUBJECT_TYPE_PUBLIC;
      p_config->auth_token_max_age = json_integer_value(json_object_get(p_config->j_params, "request-maximum-exp"));
      if (!p_config->auth_token_max_age) {
        p_config->auth_token_max_age = GLEWLWYD_AUTH_TOKEN_DEFAULT_MAX_AGE;
      }
      
      // Set sign and verification jwt and jwk
      if (r_jwt_init(&p_config->jwt_sign) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error allocating resources for jwt_sign");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }
      
      if (r_jwt_init(&p_config->oidc_resource_config->jwt) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error allocating resources for oidc_resource_config jwt");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }
      
      key = (const unsigned char *)json_string_value(json_object_get(p_config->j_params, "key"));
      key_len = json_string_length(json_object_get(p_config->j_params, "key"));
      // Set specified alg in config parameters
      if (0 == o_strcmp("rsa", json_string_value(json_object_get(p_config->j_params, "jwt-type")))) {
        if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_RS256;
          p_config->jwt_key_size = 256;
        } else if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_RS384;
          p_config->jwt_key_size = 384;
        } else { // 512
          alg = R_JWA_ALG_RS512;
          p_config->jwt_key_size = 512;
        }
      } else if (0 == o_strcmp("ecdsa", json_string_value(json_object_get(p_config->j_params, "jwt-type")))) {
        if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_ES256;
          p_config->jwt_key_size = 256;
        } else if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_ES384;
          p_config->jwt_key_size = 384;
        } else { // 512
          alg = R_JWA_ALG_ES512;
          p_config->jwt_key_size = 512;
        }
      } else if (0 == o_strcmp("rsa-pss", json_string_value(json_object_get(p_config->j_params, "jwt-type")))) {
        if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_PS256;
          p_config->jwt_key_size = 256;
        } else if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_PS384;
          p_config->jwt_key_size = 384;
        } else { // 512
          alg = R_JWA_ALG_PS512;
          p_config->jwt_key_size = 512;
        }
      } else if (0 == o_strcmp("eddsa", json_string_value(json_object_get(p_config->j_params, "jwt-type")))) {
        alg = R_JWA_ALG_EDDSA;
        p_config->jwt_key_size = 256;
      } else { // SHA
        if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_HS256;
          p_config->jwt_key_size = 256;
        } else if (0 == o_strcmp("256", json_string_value(json_object_get(p_config->j_params, "jwt-key-size")))) {
          alg = R_JWA_ALG_HS384;
          p_config->jwt_key_size = 384;
        } else { // 512
          alg = R_JWA_ALG_HS512;
          p_config->jwt_key_size = 512;
        }
      }
      
      if (json_string_length(json_object_get(p_config->j_params, "jwks-private")) || json_string_length(json_object_get(p_config->j_params, "jwks-uri"))) {
        // Extract keys from JWKS
        if (r_jwks_init(&jwks_pubkey) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwks_init");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
      
        if (r_jwks_init(&jwks_privkey) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error allocating resources for jwks_privkey");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        
        if (json_string_length(json_object_get(p_config->j_params, "jwks-uri"))) {
          if (r_jwks_import_from_uri(jwks_privkey, json_string_value(json_object_get(p_config->j_params, "jwks-uri")), p_config->x5u_flags) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwks_import_from_uri");
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "Invalid jwks_uri or jwks_uri content");
            break;
          }
        } else {
          if (r_jwks_import_from_str(jwks_privkey, json_string_value(json_object_get(p_config->j_params, "jwks-private"))) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwks_import_from_str");
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "invalid jwks cntent");
            break;
          }
        }
        
        if (r_jwks_size(jwks_privkey) == 0) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error jwks-private is empty");
          j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "jwks is empty");
          break;
        }
          
        for (index=0; index < r_jwks_size(jwks_privkey); index++) {
          jwk = r_jwks_get_at(jwks_privkey, index);
          if (r_str_to_jwa_alg(r_jwk_get_property_str(jwk, "alg")) == R_JWA_ALG_UNKNOWN) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error jwk in jwks-private at index %zu has no valid 'alg' property", index);
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "invalid alg property in jwks");
            r_jwk_free(jwk);
            jwk = NULL;
            break;
          }
          if (r_jwk_get_property_str(jwk, "kid") == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error jwk in jwks-private at index %zu has no 'kid' property", index);
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "invalid kid property in jwks");
            r_jwk_free(jwk);
            jwk = NULL;
            break;
          }
          key_type = r_jwk_key_type(jwk, NULL, p_config->x5u_flags);
          if (key_type & R_KEY_TYPE_PRIVATE) {
            r_jwk_init(&jwk_pub);
            r_jwk_extract_pubkey(jwk, jwk_pub, p_config->x5u_flags);
            r_jwks_append_jwk(jwks_pubkey, jwk_pub);
            r_jwk_free(jwk_pub);
          } else if ((key_type & R_KEY_TYPE_SYMMETRIC)) {
            r_jwks_append_jwk(jwks_pubkey, jwk);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error jwk in jwks-private at index %zu is not a private or symmetric key", index);
            j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "invalid key in jwks, only private keys are allowed");
            r_jwk_free(jwk);
            jwk = NULL;
            break;
          }
          r_jwk_free(jwk);
        }
        if (j_return != NULL) {
          break;
        }
        
        if (json_string_length(json_object_get(p_config->j_params, "default-kid"))) {
          if ((p_config->jwk_sign_default = r_jwks_get_by_kid(jwks_privkey, json_string_value(json_object_get(p_config->j_params, "default-kid")))) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error invalid default-kid");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
          if ((p_config->oidc_resource_config->jwk_verify_default = r_jwks_get_by_kid(jwks_pubkey, json_string_value(json_object_get(p_config->j_params, "default-kid")))) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error invalid default-kid");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
        } else {
          if ((p_config->jwk_sign_default = r_jwks_get_at(jwks_privkey, 0)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error getting first jwk from jwks-private");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
          if ((p_config->oidc_resource_config->jwk_verify_default = r_jwks_get_at(jwks_pubkey, 0)) == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error getting first jwk from jwks-private");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
        }
        
        if (r_jwt_add_sign_jwks(p_config->jwt_sign, jwks_privkey, NULL) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error setting sign key to jwt_priv");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
         
        if (r_jwk_key_type(p_config->jwk_sign_default, NULL, p_config->x5u_flags) & R_KEY_TYPE_SYMMETRIC) {
          jwk_pub = r_jwk_copy(p_config->jwk_sign_default);
        } else {
          r_jwk_init(&jwk_pub);
          if (r_jwk_extract_pubkey(p_config->jwk_sign_default, jwk_pub, p_config->x5u_flags) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error extracting public key");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
        }
        
        if (r_jwt_add_sign_keys(p_config->oidc_resource_config->jwt, NULL, jwk_pub) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error setting verification key to oidc_resource_config");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        
        if (r_jwt_add_sign_jwks(p_config->oidc_resource_config->jwt, NULL, jwks_pubkey) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error setting sign key to jwt_priv");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        
        if (r_jwks_init(&jwks_published) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwks_init to jwks_published");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        
        for (index=0; index<r_jwks_size(jwks_pubkey); index++) {
          jwk = r_jwks_get_at(jwks_pubkey, index);
          if (r_jwk_key_type(jwk, NULL, p_config->x5u_flags)&R_KEY_TYPE_PUBLIC) {
            r_jwks_append_jwk(jwks_published, jwk);
          }
          r_jwk_free(jwk);
        }
        
        if (r_jwks_size(jwks_published)) {
          p_config->jwks_str = r_jwks_export_to_json_str(jwks_published, 0);
        }
          
        if ((str_alg = r_jwk_get_property_str(p_config->jwk_sign_default, "alg")) != NULL) {
          if (0 == o_strcmp("HS256", str_alg)) {
            alg = R_JWA_ALG_HS256;
            p_config->jwt_key_size = 256;
          } else if (0 == o_strcmp("HS384", str_alg)) {
            alg = R_JWA_ALG_HS384;
            p_config->jwt_key_size = 384;
          } else if (0 == o_strcmp("HS512", str_alg)) {
            alg = R_JWA_ALG_HS512;
            p_config->jwt_key_size = 512;
          } else if (0 == o_strcmp("RS256", str_alg)) {
            alg = R_JWA_ALG_RS256;
            p_config->jwt_key_size = 256;
          } else if (0 == o_strcmp("RS384", str_alg)) {
            alg = R_JWA_ALG_RS384;
            p_config->jwt_key_size = 384;
          } else if (0 == o_strcmp("RS512", str_alg)) {
            alg = R_JWA_ALG_RS512;
            p_config->jwt_key_size = 512;
          } else if (0 == o_strcmp("ES256", str_alg)) {
            alg = R_JWA_ALG_ES256;
            p_config->jwt_key_size = 256;
          } else if (0 == o_strcmp("ES384", str_alg)) {
            alg = R_JWA_ALG_ES384;
            p_config->jwt_key_size = 384;
          } else if (0 == o_strcmp("ES512", str_alg)) {
            alg = R_JWA_ALG_ES512;
            p_config->jwt_key_size = 512;
          } else if (0 == o_strcmp("PS256", str_alg)) {
            alg = R_JWA_ALG_PS256;
            p_config->jwt_key_size = 256;
          } else if (0 == o_strcmp("PS384", str_alg)) {
            alg = R_JWA_ALG_PS384;
            p_config->jwt_key_size = 384;
          } else if (0 == o_strcmp("PS512", str_alg)) {
            alg = R_JWA_ALG_PS512;
            p_config->jwt_key_size = 512;
          } else if (0 == o_strcmp("EdDSA", str_alg)) {
            alg = R_JWA_ALG_EDDSA;
            p_config->jwt_key_size = 256;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error invalid alg value from default jwk");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
        }
      } else {
        // Exttract key from PEM
        if (r_jwk_init(&p_config->jwk_sign_default) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwk_init jwk_sign_default");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        
        if (r_jwk_init(&p_config->oidc_resource_config->jwk_verify_default) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwk_init jwk_verify_default");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        
        if (0 == o_strcmp("sha", json_string_value(json_object_get(p_config->j_params, "jwt-type")))) {
          if (r_jwk_import_from_symmetric_key(p_config->jwk_sign_default, key, key_len) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwk_import_from_symmetric_key");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
          if (r_jwk_import_from_symmetric_key(p_config->oidc_resource_config->jwk_verify_default, key, key_len) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwk_import_from_symmetric_key");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
        } else {
          if (r_jwk_import_from_pem_der(p_config->jwk_sign_default, R_X509_TYPE_PRIVKEY, R_FORMAT_PEM, key, key_len) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwk_import_from_pem_der (1)");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
          r_jwk_delete_property_str(p_config->jwk_sign_default, "kid");
          if (r_jwk_import_from_pem_der(p_config->oidc_resource_config->jwk_verify_default, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (const unsigned char *)json_string_value(json_object_get(p_config->j_params, "cert")), json_string_length(json_object_get(p_config->j_params, "cert"))) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwt_add_sign_keys_pem_der (2)");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
          r_jwk_delete_property_str(p_config->oidc_resource_config->jwk_verify_default, "kid");
        }
        
        if (r_jwt_add_sign_keys(p_config->jwt_sign, p_config->jwk_sign_default, NULL) != RHN_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwt_add_sign_keys (2)");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        
        if (0 != o_strcmp("sha", json_string_value(json_object_get(p_config->j_params, "jwt-type")))) {
          if (r_jwk_init(&jwk_pub) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwk_init (2)");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }

          if (r_jwks_init(&jwks_pubkey) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwks_init (2)");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
          
          if (r_jwk_import_from_pem_der(jwk_pub, R_X509_TYPE_PUBKEY, R_FORMAT_PEM, (const unsigned char *)json_string_value(json_object_get(p_config->j_params, "cert")), json_string_length(json_object_get(p_config->j_params, "cert"))) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwk_import_from_pem_der (2)");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
          r_jwk_delete_property_str(jwk_pub, "kid");
          
          if (json_array_size(json_object_get(p_config->j_params, "jwks-x5c"))) {
            json_array_foreach(json_object_get(p_config->j_params, "jwks-x5c"), index, j_element) {
              if (r_jwk_append_property_array(jwk_pub, "x5c", json_string_value(j_element)) != RHN_OK) {
                y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - oidc - Error r_jwk_append_property_array at index %zu", index);
                j_return = json_pack("{si}", "result", G_ERROR);
                break;
              }
            }
          }
          r_jwk_set_property_str(jwk_pub, "use", "sig");
          r_jwk_set_property_str(jwk_pub, "alg", r_jwa_alg_to_str(alg));
          
          if (r_jwks_append_jwk(jwks_pubkey, jwk_pub) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwks_append_jwk");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
          p_config->jwks_str = r_jwks_export_to_json_str(jwks_pubkey, 0);
          
          if (r_jwt_add_sign_jwks(p_config->oidc_resource_config->jwt, NULL, jwks_pubkey) != RHN_OK) {
            y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwt_add_sign_jwks");
            j_return = json_pack("{si}", "result", G_ERROR);
            break;
          }
        }
      }

      if (r_jwt_set_sign_alg(p_config->jwt_sign, alg) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwt_set_sign_alg");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }
      
      if (r_jwt_set_sign_alg(p_config->oidc_resource_config->jwt, alg) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwt_set_sign_alg (2)");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }
      
      if (jwt_autocheck(p_config) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error jwt_autocheck");
        j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "Error jwt_autocheck");
        break;
      }
      
      p_config->oidc_resource_config->alg = alg;
      if (r_jwk_init(&jwk) != RHN_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error r_jwk_init");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }
      
      // Add endpoints
      y_log_message(Y_LOG_LEVEL_INFO, "Add endpoints with plugin prefix %s", name);
      if (config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_authorization, (void*)*cls) != G_OK || 
         config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "auth/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_authorization, (void*)*cls) != G_OK || 
         config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "token/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_token, (void*)*cls) != G_OK || 
         config->glewlwyd_callback_add_plugin_endpoint(config, "*", name, "userinfo/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_userinfo, (void*)*cls) != G_OK || 
         config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "userinfo/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_get_userinfo, (void*)*cls) != G_OK || 
         config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "userinfo/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_get_userinfo, (void*)*cls) != G_OK || 
         config->glewlwyd_callback_add_plugin_endpoint(config, "*", name, "userinfo/", GLEWLWYD_CALLBACK_PRIORITY_CLOSE, &callback_oidc_clean, NULL) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "token/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_glewlwyd_session_or_token, (void*)*cls) != G_OK || 
         config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "token/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_refresh_token_list_get, (void*)*cls) != G_OK || 
         config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "token/", GLEWLWYD_CALLBACK_PRIORITY_CLOSE, &callback_oidc_clean, NULL) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "DELETE", name, "token/*", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_glewlwyd_session_or_token, (void*)*cls) != G_OK || 
         config->glewlwyd_callback_add_plugin_endpoint(config, "DELETE", name, "token/:token_hash", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_disable_refresh_token, (void*)*cls) != G_OK || 
         config->glewlwyd_callback_add_plugin_endpoint(config, "DELETE", name, "token/*", GLEWLWYD_CALLBACK_PRIORITY_CLOSE, &callback_oidc_clean, NULL) != G_OK || 
         config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, ".well-known/openid-configuration", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_discovery, (void*)*cls) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "jwks", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_get_jwks, (void*)*cls) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - oidc - Error adding endpoints");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }

      if (json_object_get(p_config->j_params, "introspection-revocation-allowed") == json_true()) {
        if ((p_config->introspect_revoke_resource_config = o_malloc(sizeof(struct _oidc_resource_config))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - oidc - Error allocating resources for introspect_revoke_resource_config");
          j_return = json_pack("{si}", "result", G_ERROR);
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
        p_config->introspect_revoke_resource_config->jwt = r_jwt_copy(p_config->oidc_resource_config->jwt);
        p_config->introspect_revoke_resource_config->jwk_verify_default = r_jwk_copy(p_config->oidc_resource_config->jwk_verify_default);
        p_config->introspect_revoke_resource_config->alg = alg;
        if (
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "introspect/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_intropect_revoke, (void*)*cls) != G_OK || 
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "introspect/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_introspection, (void*)*cls) != G_OK || 
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "introspect/", GLEWLWYD_CALLBACK_PRIORITY_CLOSE, &callback_oidc_clean, NULL) != G_OK ||
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "revoke/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_intropect_revoke, (void*)*cls) != G_OK || 
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "revoke/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_revocation, (void*)*cls) != G_OK ||
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "revoke/", GLEWLWYD_CALLBACK_PRIORITY_CLOSE, &callback_oidc_clean, NULL) != G_OK
          ) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - oidc - Error adding introspect/revoke endpoints");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
      }
      
      if (json_object_get(p_config->j_params, "register-client-allowed") == json_true()) {
        if ((p_config->client_register_resource_config = o_malloc(sizeof(struct _oidc_resource_config))) == NULL) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - oidc - Error allocating resources for client_register_resource_config");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        p_config->client_register_resource_config->method = G_METHOD_HEADER;
        p_config->client_register_resource_config->oauth_scope = NULL;
        json_array_foreach(json_object_get(p_config->j_params, "register-client-auth-scope"), index, j_element) {
          if (p_config->client_register_resource_config->oauth_scope == NULL) {
            p_config->client_register_resource_config->oauth_scope = o_strdup(json_string_value(j_element));
          } else {
            p_config->client_register_resource_config->oauth_scope = mstrcatf(p_config->client_register_resource_config->oauth_scope, " %s", json_string_value(j_element));
          }
        }
        p_config->client_register_resource_config->realm = NULL;
        p_config->client_register_resource_config->accept_access_token = 1;
        p_config->client_register_resource_config->accept_client_token = 1;
        p_config->client_register_resource_config->jwt = r_jwt_copy(p_config->oidc_resource_config->jwt);
        p_config->client_register_resource_config->jwk_verify_default = r_jwk_copy(p_config->oidc_resource_config->jwk_verify_default);
        p_config->client_register_resource_config->alg = alg;
        if (
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "register/", GLEWLWYD_CALLBACK_PRIORITY_AUTHENTICATION, &callback_check_registration, (void*)*cls) != G_OK || 
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "register/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_client_registration, (void*)*cls) != G_OK || 
          config->glewlwyd_callback_add_plugin_endpoint(config, "POST", name, "register/", GLEWLWYD_CALLBACK_PRIORITY_CLOSE, &callback_oidc_clean, NULL) != G_OK
          ) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - oidc - Error adding register endpoints");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
      }
      
      if (json_object_get(p_config->j_params, "session-management-allowed") == json_true()) {
        if (
         config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "end_session/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_end_session, (void*)*cls) != G_OK ||
         config->glewlwyd_callback_add_plugin_endpoint(config, "GET", name, "check_session_iframe/", GLEWLWYD_CALLBACK_PRIORITY_APPLICATION, &callback_oidc_check_session_iframe, (void*)*cls) != G_OK
        ) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - oidc - Error adding session-management endpoints");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
        
        if (generate_check_session_iframe(p_config) != G_OK) {
          y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - oidc - Error generate_check_session_iframe");
          j_return = json_pack("{si}", "result", G_ERROR);
          break;
        }
      }
      
      if (generate_discovery_content(p_config) != G_OK) {
        y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - oidc - Error generate_discovery_content");
        j_return = json_pack("{si}", "result", G_ERROR);
        break;
      }
      
    } while (0);
    json_decref(j_result);
    r_jwk_free(jwk_pub);
    r_jwk_free(jwk);
    r_jwks_free(jwks_privkey);
    r_jwks_free(jwks_pubkey);
    r_jwks_free(jwks_published);
    if (j_return == NULL) {
      j_return = json_pack("{si}", "result", G_OK);
    } else {
      if (p_config != NULL) {
        if (p_config->introspect_revoke_resource_config != NULL) {
          o_free(p_config->introspect_revoke_resource_config->oauth_scope);
          o_free(p_config->introspect_revoke_resource_config->realm);
          r_jwt_free(p_config->introspect_revoke_resource_config->jwt);
          r_jwk_free(p_config->introspect_revoke_resource_config->jwk_verify_default);
          o_free(p_config->introspect_revoke_resource_config);
        }
        if (p_config->client_register_resource_config != NULL) {
          o_free(p_config->client_register_resource_config->oauth_scope);
          o_free(p_config->client_register_resource_config->realm);
          r_jwt_free(p_config->client_register_resource_config->jwt);
          r_jwk_free(p_config->client_register_resource_config->jwk_verify_default);
          o_free(p_config->client_register_resource_config);
        }
        if (p_config->oidc_resource_config != NULL) {
          o_free(p_config->oidc_resource_config->oauth_scope);
          o_free(p_config->oidc_resource_config->realm);
          r_jwt_free(p_config->oidc_resource_config->jwt);
          r_jwk_free(p_config->oidc_resource_config->jwk_verify_default);
          o_free(p_config->oidc_resource_config);
        }
        r_jwt_free(p_config->jwt_sign);
        r_jwk_free(p_config->jwk_sign_default);
        json_decref(p_config->j_params);
        pthread_mutex_destroy(&p_config->insert_lock);
        o_free(p_config->discovery_str);
        o_free(p_config->jwks_str);
        o_free(p_config->check_session_iframe);
        o_free(p_config);
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "oidc protocol_init - Error allocating resources for cls");
    o_free(*cls);
    *cls = NULL;
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  return j_return;
}

int plugin_module_close(struct config_plugin * config, const char * name, void * cls) {
  if (cls != NULL) {
    y_log_message(Y_LOG_LEVEL_INFO, "Close plugin Glewlwyd OpenID Connect '%s'", name);
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "auth/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "auth/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "token/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "*", name, "userinfo/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "userinfo/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "userinfo/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "token/");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "DELETE", name, "token/:token_hash");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "DELETE", name, "token/*");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, ".well-known/openid-configuration");
    config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "jwks");
    if (json_object_get(((struct _oidc_config *)cls)->j_params, "session-management-allowed") == json_true()) {
      config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "end_session/");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "GET", name, "check_session_iframe/");
    }
    if (((struct _oidc_config *)cls)->introspect_revoke_resource_config != NULL) {
      config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "introspect/");
      config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "revoke/");
      o_free(((struct _oidc_config *)cls)->introspect_revoke_resource_config->oauth_scope);
      o_free(((struct _oidc_config *)cls)->introspect_revoke_resource_config->realm);
      r_jwt_free(((struct _oidc_config *)cls)->introspect_revoke_resource_config->jwt);
      r_jwk_free(((struct _oidc_config *)cls)->introspect_revoke_resource_config->jwk_verify_default);
      o_free(((struct _oidc_config *)cls)->introspect_revoke_resource_config);
    }
    if (((struct _oidc_config *)cls)->client_register_resource_config != NULL) {
      config->glewlwyd_callback_remove_plugin_endpoint(config, "POST", name, "register/");
      o_free(((struct _oidc_config *)cls)->client_register_resource_config->oauth_scope);
      o_free(((struct _oidc_config *)cls)->client_register_resource_config->realm);
      r_jwt_free(((struct _oidc_config *)cls)->client_register_resource_config->jwt);
      r_jwk_free(((struct _oidc_config *)cls)->client_register_resource_config->jwk_verify_default);
      o_free(((struct _oidc_config *)cls)->client_register_resource_config);
    }
    if (((struct _oidc_config *)cls)->oidc_resource_config != NULL) {
      o_free(((struct _oidc_config *)cls)->oidc_resource_config->oauth_scope);
      o_free(((struct _oidc_config *)cls)->oidc_resource_config->realm);
      r_jwt_free(((struct _oidc_config *)cls)->oidc_resource_config->jwt);
      r_jwk_free(((struct _oidc_config *)cls)->oidc_resource_config->jwk_verify_default);
      o_free(((struct _oidc_config *)cls)->oidc_resource_config);
    }
    r_jwt_free(((struct _oidc_config *)cls)->jwt_sign);
    r_jwk_free(((struct _oidc_config *)cls)->jwk_sign_default);
    json_decref(((struct _oidc_config *)cls)->j_params);
    pthread_mutex_destroy(&((struct _oidc_config *)cls)->insert_lock);
    o_free(((struct _oidc_config *)cls)->discovery_str);
    o_free(((struct _oidc_config *)cls)->jwks_str);
    o_free(((struct _oidc_config *)cls)->check_session_iframe);
    o_free(cls);
  }
  return G_OK;
}

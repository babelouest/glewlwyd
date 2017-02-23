/**
 *
 * Glewlwyd OAuth2 Authorization token check
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

#include <string.h>
#include <time.h>
#include <orcania.h>
#include <ulfius.h>
#include <jansson.h>

#include "glewlwyd_resource.h"

/**
 * Validates if an access_token is valid
 */
json_t * access_token_check(struct _glewlwyd_client_config * config, const char * header_value) {
  json_t * j_token = access_token_get(config, header_value), * j_return;
  time_t now;
  json_int_t expiration;
  
  if (check_result_value(j_token, G_OK)) {
    // Token is valid, check type and expiration date
    time(&now);
    expiration = json_integer_value(json_object_get(json_object_get(j_token, "grants"), "iat")) + json_integer_value(json_object_get(json_object_get(j_token, "grants"), "expires_in"));
    if (now < expiration && 0 == nstrcmp("access_token", json_string_value(json_object_get(json_object_get(j_token, "grants"), "type")))) {
      j_return = json_copy(j_token);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
  } else {
    j_return = json_copy(j_token);
  }
  json_decref(j_token);
  return j_return;
}

/**
 * check if bearer token has the specified scope
 */
int callback_check_glewlwyd_scope (const struct _u_request * request, struct _u_response * response, void * user_data) {
  struct _glewlwyd_client_config * config = (struct _glewlwyd_client_config *)user_data;
  json_t * j_access_token = NULL;
  int res = U_ERROR_UNAUTHORIZED, i, count;
  char ** scope_list;
  
  j_access_token = access_token_check(config, u_map_get(request->map_header, AUTHORIZATION_HEADER));
  if (check_result_value(j_access_token, G_OK)) {
    count = split_string(json_string_value(json_object_get(json_object_get(j_access_token, "grants"), "scope")), " ", &scope_list);
    for (i=0; count > 0 && scope_list[i] != NULL; i++) {
      if (strcmp(scope_list[i], config->oauth_scope) == 0) {
        res = U_OK;
        break;
      }
    }
    free_string_array(scope_list);
  } else if (check_result_value(j_access_token, G_ERROR)) {
    res = U_ERROR;
  }
  json_decref(j_access_token);
  return res;
}

json_t * access_token_get(struct _glewlwyd_client_config * config, const char * header_value) {
  json_t * j_return, * j_grants;
  jwt_t * jwt = NULL;
  char  * grants;
  const char * token_value;
  
  if (header_value != NULL) {
    if (strstr(header_value, PREFIX_BEARER) == header_value) {
      token_value = header_value + strlen(PREFIX_BEARER);
      if (!jwt_decode(&jwt, token_value, (const unsigned char *)config->jwt_decode_key, strlen(config->jwt_decode_key)) && jwt_get_alg(jwt) == config->jwt_alg) {
        grants = jwt_get_grants_json(jwt, NULL);
        j_grants = json_loads(grants, JSON_DECODE_ANY, NULL);
        if (j_grants != NULL) {
          j_return = json_pack("{siso}", "result", G_OK, "grants", j_grants);
        } else {
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        free(grants);
      } else {
        j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
      }
      jwt_free(jwt);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
    }
  } else {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_return;
}

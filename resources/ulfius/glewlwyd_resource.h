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
#include <jwt.h>

#define G_OK                 0
#define G_ERROR              1
#define G_ERROR_UNAUTHORIZED 2

#define PREFIX_BEARER        "Bearer "
#define AUTHORIZATION_HEADER "Authorization"

struct _glewlwyd_client_config {
  char *    oauth_scope;
  char *    jwt_decode_key;
  jwt_alg_t jwt_alg;
};

int callback_check_glewlwyd_scope (const struct _u_request * request, struct _u_response * response, void * user_data);
json_t * access_token_get(struct _glewlwyd_client_config * config, const char * header_value);
json_t * access_token_check(struct _glewlwyd_client_config * config, const char * header_value);

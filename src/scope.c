/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * scope management functions definition
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
#include "glewlwyd.h"

json_t * get_scope_list(struct config_elements * config) {
  json_t * j_query, * j_result, * j_return;
  int res;

  j_query = json_pack("{sss[sss]}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "columns",
                        "gs_name",
                        "gs_display_name",
                        "gs_description");
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_return = json_pack("{siso}", "result", G_OK, "scope", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_scope_list - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

json_t * get_scope(struct config_elements * config, const char * scope) {
  json_t * j_query, * j_result, * j_return;
  int res;

  j_query = json_pack("{sss[sss]s{ss}}",
                      "table",
                      GLEWLWYD_TABLE_SCOPE,
                      "columns",
                        "gs_name",
                        "gs_display_name",
                        "gs_description",
                      "where",
                        "gs_name",
                        scope);
  res = h_select(config->conn, j_query, &j_result, NULL);
  json_decref(j_query);
  if (res == H_OK) {
    j_return = json_pack("{siso}", "result", G_OK, "scope", j_result);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_scope - Error executing j_query");
    j_return = json_pack("{si}", "result", G_ERROR_DB);
  }
  return j_return;
}

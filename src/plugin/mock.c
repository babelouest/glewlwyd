/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * mock plugin
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

#include "../glewlwyd-common.h"

json_t * plugin_module_load(struct config_plugin * config) {
  return json_pack("{sisssssss{}}",
                   "result",
                   G_OK,
                   "name",
                   "mock",
                   "display_name",
                   "Mock plugin",
                   "description",
                   "Mock plugin description",
                   "parameters");
}

int plugin_module_unload(struct config_plugin * config) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "plugin_module_unload - success");
  return G_OK;
}

int plugin_module_init(struct config_plugin * config, json_t * j_parameters, void ** cls) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "plugin_module_init - success");
  return G_OK;
}

int plugin_module_close(struct config_plugin * config, void * cls) {
  y_log_message(Y_LOG_LEVEL_DEBUG, "plugin_module_close - success");
  return G_OK;
}

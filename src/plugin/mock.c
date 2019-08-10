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

/**
 *
 * Note on plugin
 *
 * By design a plugin has on those 4 functions mandatory:
 * - json_t * plugin_module_load(struct config_plugin * config)
 * - int plugin_module_unload(struct config_plugin * config)
 * - int plugin_module_init(struct config_plugin * config, const char * name, json_t * j_parameters, void ** cls)
 * - int plugin_module_close(struct config_plugin * config, const char * name, void * cls)
 *
 * The purpose of Glewlwyd core is to provide a environment to manage users, clients, connections and scopes, and to provide webservices as modules
 * Although, the purpose of a plugin is to provide web services for specific goals.
 *
 * To achieve this purpose, the structure config_plugin mostly contains pointer to glewlwyd functions:
 *
 * struct config_plugin {
 *   struct config_elements * glewlwyd_config;
 *   int      (* glewlwyd_callback_add_plugin_endpoint)(struct config_plugin * config, const char * method, const char * name, const char * url, unsigned int priority, int (* callback)(const struct _u_request * request, struct _u_response * response, void * user_data), void * user_data);
 *   int      (* glewlwyd_callback_remove_plugin_endpoint)(struct config_plugin * config, const char * method, const char * name, const char * url);
 *   
 *   // Session callback functions
 *   json_t * (* glewlwyd_callback_check_session_valid)(struct config_plugin * config, const struct _u_request * request, const char * scope_list);
 *   json_t * (* glewlwyd_callback_check_user_valid)(struct config_plugin * config, const char * username, const char * password, const char * scope_list);
 *   json_t * (* glewlwyd_callback_check_client_valid)(struct config_plugin * config, const char * client_id, const char * password);
 *   int      (* glewlwyd_callback_trigger_session_used)(struct config_plugin * config, const struct _u_request * request, const char * scope_list);
 *   
 *   // Client callback functions
 *   json_t * (* glewlwyd_callback_get_client_granted_scopes)(struct config_plugin * config, const char * client_id, const char * username, const char * scope_list);
 *   
 *   // User CRUD
 *   json_t * (* glewlwyd_plugin_callback_get_user_list)(struct config_plugin * config, const char * pattern, size_t offset, size_t limit);
 *   json_t * (* glewlwyd_plugin_callback_get_user)(struct config_plugin * config, const char * username);
 *   json_t * (* glewlwyd_plugin_callback_get_user_profile)(struct config_plugin * config, const char * username);
 *   int      (* glewlwyd_plugin_callback_add_user)(struct config_plugin * config, json_t * j_user);
 *   int      (* glewlwyd_plugin_callback_set_user)(struct config_plugin * config, const char * username, json_t * j_user);
 *   int      (* glewlwyd_plugin_callback_delete_user)(struct config_plugin * config, const char * username);
 *   
 *   // Misc functions
 *   char   * (* glewlwyd_callback_get_plugin_external_url)(struct config_plugin * config, const char * name);
 *   char   * (* glewlwyd_callback_get_login_url)(struct config_plugin * config, const char * client_id, const char * scope_list, const char * callback_url, struct _u_map * additional_parameters);
 *   char   * (* glewlwyd_callback_generate_hash)(struct config_plugin * config, const char * data);
 * };
 *
 * The functions glewlwyd_callback_add_plugin_endpoint and glewlwyd_callback_remove_plugin_endpoint exist to dynamically add or remove endpoints
 * A plugin endpoint url parameter is relative to glewlwyd's api prefix, e.g. /api/, this api prefix will be added to the endpoint url by Glewlwyd
 * Also, a plugin endpoint priority is relative to the value GLEWLWYD_CALLBACK_PRIORITY_PLUGIN, so the endpoint is supposed to have a lower priority than Glewlwyd's core endpoints
 *
 */

/**
 * 
 * plugin_module_load
 * 
 * Executed once when Glewlwyd service is started
 * Used to identify the module and to show its parameters on init
 * You can also use it to load resources that are required once for all
 * instance modules for example
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  name: string, mandatory, name of the module, must be unique among other scheme modules
 *                  display_name: string, optional, long name of the module
 *                  description: string, optional, description for the module
 *                  parameters: object, optional, parameters description for the module
 *                }
 * 
 *                Example:
 *                {
 *                  result: G_OK,
 *                  name: "mock",
 *                  display_name: "Mock scheme module",
 *                  description: "Mock scheme module for glewlwyd tests",
 *                  parameters: {
 *                    mock-value: {
 *                      type: "string",
 *                      mandatory: true
 *                    }
 *                  }
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
json_t * plugin_module_load(struct config_plugin * config) {
  UNUSED(config);
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

/**
 * 
 * plugin_module_unload
 * 
 * Executed once when Glewlwyd service is stopped
 * You can use it to release resources that are required once for all
 * instance modules for example
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
int plugin_module_unload(struct config_plugin * config) {
  UNUSED(config);
  y_log_message(Y_LOG_LEVEL_DEBUG, "plugin_module_unload - success");
  return G_OK;
}

/**
 * 
 * plugin_module_init
 * 
 * Initialize an instance of this module declared in Glewlwyd service.
 * If required, you must dynamically allocate a pointer to the configuration
 * for this instance and pass it to *cls
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, G_ERROR_PARAM on input parameters error, another value on error)
 *                  error: array of strings containg the list of input errors, mandatory on result G_ERROR_PARAM, ignored otherwise
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter j_parameters: used to initialize an instance in JSON format
 *                          The module must validate itself its parameters
 * @parameter cls: will contain an allocated void * pointer that will be sent back
 *                 as void * in all module functions
 * 
 */
json_t * plugin_module_init(struct config_plugin * config, const char * name, json_t * j_parameters, void ** cls) {
  UNUSED(config);
  UNUSED(name);
  UNUSED(cls);
  json_t * j_return;
  
  if (json_object_get(j_parameters, "error") == NULL) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "plugin_module_init - success");
    j_return = json_pack("{si}", "result", G_OK);
  } else {
    j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "Error input parameters");
  }
  return j_return;
}

/**
 * 
 * plugin_module_close
 * 
 * Close an instance of this module declared in Glewlwyd service.
 * You must free the memory previously allocated in
 * the client_module_init function as void * cls
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter cls: pointer to the void * cls value allocated in client_module_init
 * 
 */
int plugin_module_close(struct config_plugin * config, const char * name, void * cls) {
  UNUSED(config);
  UNUSED(name);
  UNUSED(cls);
  y_log_message(Y_LOG_LEVEL_DEBUG, "plugin_module_close - success");
  return G_OK;
}

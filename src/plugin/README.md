# Glewlwyd Plugins

A Glewlwyd plugin is built as a library and loaded at startup. It must contain a specific set of functions available to glewlwyd to work properly. A plugin is designed to build workflows of any kind.

Currently, the workflows [OAuth 2](../../docs/OAUTH2.md) and [OpenID Connect](../../docs/OIDC.md) are available.

Plugins can be use to perform (but not only):
- Authentication workflows (OAuth, OAuth 2, SAML, etc.)
- New user registration workflow
- Forgot password workflow

A Glewlwyd plugin can access the entire data and functions available to Glewlwyd service. There is no limitation to its access. Therefore, Glewlwyd plugins must be carefully designed and considered friendly. All data returned as `json_t *` or `char *` must be dynamically allocated, because they will be cleaned up by Glewlwyd after use.

Currently, the following user backend plugins are available:
- [OAuth 2](protocol_oauth2.c)
- [OpenID Connect](protocol_oidc.c)
- [Register new user](register.c)

Technically, a plugin is a small web application that is loaded and instaciated by Glewlwyd service. Therefore a plugin has only 4 functions to implement. The plugin has access to Glewlwyd's callback function such as managing users and clients, or managing new API endpoints. The goal is to create a set of APIs, then the APIs will perform actions specific for the plugin.

The endpoints must be added in the init function, and removed in the close function.

A Glewlwyd plugin requires the library [Jansson](https://github.com/akheron/Jansson).

You can check out the existing plugins for inspiration. You can start from the fake plugin [mock.c](mock.c) to build your own.

A pointer of `struct config_plugin` is passed to all the mandatory functions. This pointer gives access to some Glewlwyd data and some callback functions used to achieve specific actions.

The definition of the structure is the following:

```C
/**
 * Structure given to all plugin functions that will contain configuration on the
 * application host, and pointer to functions of the application host
 */
struct config_plugin {
  /* General configuration of the Glewlwyd instance */
  struct config_elements * glewlwyd_config;
  /* Add a new HTTP endpoint, this endopoint will be available at the address http[s]://<glewlwyd_server>/<glewlwyd_api_prefix>/<name>/<url>, example: https://localhost:4953/api/glwd/auth */
  int      (* glewlwyd_callback_add_plugin_endpoint)(struct config_plugin * config, const char * method, const char * name, const char * url, unsigned int priority, int (* callback)(const struct _u_request * request, struct _u_response * response, void * user_data), void * user_data);
  /* Remove en existing endpoint */
  int      (* glewlwyd_callback_remove_plugin_endpoint)(struct config_plugin * config, const char * method, const char * name, const char * url);
  
  // Session callback functions
  /* Return the validity of a session with the specified scopes, the result will tell if scopes require registration or scheme authentication */
  json_t * (* glewlwyd_callback_check_session_valid)(struct config_plugin * config, const struct _u_request * request, const char * scope_list);
  /* Check if a password is valid for the user and if the scope list is available to the user */
  json_t * (* glewlwyd_callback_check_user_valid)(struct config_plugin * config, const char * username, const char * password, const char * scope_list);
  /* Check if a password is valid for the client and if the scope list is available to the client */
  json_t * (* glewlwyd_callback_check_client_valid)(struct config_plugin * config, const char * client_id, const char * password);
  /* Tell Glewlwyd that the current session has been triggered, to invalidate some scheme session if necessary */
  int      (* glewlwyd_callback_trigger_session_used)(struct config_plugin * config, const struct _u_request * request, const char * scope_list);
  /* Return the last successful authentication with any scheme of the current session */
  time_t   (* glewlwyd_callback_get_session_age)(struct config_plugin * config, const struct _u_request * request, const char * scope_list);
  
  // Client callback functions
  /* Return the scopes the user had granted access to the client */
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
  json_t * (* glewlwyd_plugin_callback_scheme_register)(struct config_plugin * config, const char * mod_name, const struct _u_request * http_request, const char * username, json_t * j_scheme_data);
  json_t * (* glewlwyd_plugin_callback_scheme_register_get)(struct config_plugin * config, const char * mod_name, const struct _u_request * http_request, const char * username);
  int      (* glewlwyd_plugin_callback_scheme_deregister)(struct config_plugin * config, const char * mod_name, const char * username);
  int      (* glewlwyd_plugin_callback_scheme_can_use)(struct config_plugin * config, const char * mod_name, const char * username);
  
  // Misc functions
  /* Return this plugin external url root */
  char   * (* glewlwyd_callback_get_plugin_external_url)(struct config_plugin * config, const char * name);
  /* Return the external url of the login page */
  char   * (* glewlwyd_callback_get_login_url)(struct config_plugin * config, const char * client_id, const char * scope_list, const char * callback_url, struct _u_map * additional_parameters);
  /* Generates a hashed value of the data given using the format "{hash_type}<hash_value>", the hash type is specified in the config file */
  char   * (* glewlwyd_callback_generate_hash)(struct config_plugin * config, const char * data);
};
```

A plugin must have the following functions defined and available:

```C
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
 * {
 *    result: number (G_OK on success, another value on error)
 *    name: string, mandatory, name of the module, must be unique among other scheme modules
 *    display_name: string, optional, long name of the module
 *    description: string, optional, description for the module
 *    parameters: object, optional, parameters description for the module
 *  }
 * 
 *  Example:
 *  {
 *    result: G_OK,
 *    name: "mock",
 *    display_name: "Mock scheme module",
 *    description: "Mock scheme module for glewlwyd tests",
 *    parameters: {
 *      mock-value: {
 *        type: "string",
 *        mandatory: true
 *      }
 *    }
 *  }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
json_t * plugin_module_load(struct config_plugin * config);
```

```C
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
int plugin_module_unload(struct config_plugin * config);
```

```C
/**
 * 
 * plugin_module_init
 * 
 * Initialize an instance of this module declared in Glewlwyd service.
 * If required, you must dynamically allocate a pointer to the configuration
 * for this instance and pass it to *cls
 * 
 * @return value: a json_t * value with the following pattern:
 * {
 *   result: number (G_OK on success, G_ERROR_PARAM on input parameters error, another value on error)
 *   error: array of strings containg the list of input errors, mandatory on result G_ERROR_PARAM, ignored otherwise
 * }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter j_parameters: used to initialize an instance in JSON format
 *                          The module must validate itself its parameters
 * @parameter cls: will contain an allocated void * pointer that will be sent back
 *                 as void * in all module functions
 * 
 */
json_t * plugin_module_init(struct config_plugin * config, const char * name, json_t * j_parameters, void ** cls);
```

```C
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
int plugin_module_close(struct config_plugin * config, const char * name, void * cls);
```

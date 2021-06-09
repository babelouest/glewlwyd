# Glewlwyd User Middleware Backend Modules

A Glewlwyd module is built as a library and loaded at startup. It must contain a specific set of functions available to glewlwyd to work properly.

A Glewlwyd module can access the entire data and functions available to Glewlwyd service. There is no limitation to its access. Therefore, Glewlwyd modules must be carefully designed and considered friendly. All data returned as `json_t *` or `char *` must be dynamically allocated, because they will be cleaned up by Glewlwyd after use.

A user middleware module is intended to improve and extend a user object by updating its attributes (add, update or remove attributes), for example, adding groups and access-levels to an existing user when these metadata are not stored in the LDAP backend but in a different location.

Currently, the following user middleware backend modules are available:

A user middleware backend module is used to manage users in a specific backend environment.
It is intended to:
- update a list user object returned by the user backend
- update a specific user object returned by the user backend
- update a user object returned by the API to be stored by the user backend

A user is defined by attributes. The following attributes are mandatory for every user:

```javascript
{
  "username": string, identifies the user, must be unique
  "scope": array of string, list of scopes available to the user
  "enabled": boolean, set this value to false will make the user unable to authenticate or do anything in Glewlwyd
}
```

A user middleware module is allowed to change any attribute of the user, except for the `username` attribute, it is allowed to add or remove attributes too, but be careful to respect the mandatory format below after the middleware process. See user modules for more information.

A Glewlwyd module requires the library [Jansson](https://github.com/akheron/Jansson).

You can check out the existing modules for inspiration. You can start from the fake module [mock.c](mock.c) to build your own.

```C
struct config_module {
  /* External url to access to the Glewlwyd instance */
  const char              * external_url;
  /* relative url to access to the login page */
  const char              * login_url;
  /* value of the admin scope */
  const char              * admin_scope;
  /* Value of the profile scope */
  const char              * profile_scope;
  /* connection to the database via hoel library */
  struct _h_connection    * conn;
  /* Digest agorithm defined in the configuration file */
  digest_algorithm          hash_algorithm;
  /* General configuration of the Glewlwyd instance */
  struct config_elements  * glewlwyd_config;
  /* Callback function to retrieve a specific user */
  json_t               * (* glewlwyd_module_callback_get_user)(struct config_module * config, const char * username);
  /* Callback function to update a specific user */
  int                    (* glewlwyd_module_callback_set_user)(struct config_module * config, const char * username, json_t * j_user);
  /* Callback function to validate a user password */
  int                    (* glewlwyd_module_callback_check_user_password)(struct config_module * config, const char * username, const char * password);
  /* Callback function to validate a session */
  json_t               * (* glewlwyd_module_callback_check_user_session)(struct config_module * config, const struct _u_request * request, const char * username);
};
```

A user middleware module must have the following functions defined and available:

```C
/**
 * 
 * user_middleware_module_load
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
json_t * user_middleware_module_load(struct config_module * config);
```

```C
/**
 * 
 * user_middleware_module_unload
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
int user_middleware_module_unload(struct config_module * config);
```

```C
/**
 * 
 * user_middleware_module_init
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
json_t * user_middleware_module_init(struct config_module * config, json_t * j_parameters, void ** cls);
```

```C
/**
 * 
 * user_middleware_module_close
 * 
 * Close an instance of this module declared in Glewlwyd service.
 * You must free the memory previously allocated in
 * the user_module_init function as void * cls
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_close(struct config_module * config, void * cls);
```

```C
/**
 *
 * user_middleware_module_get_list
 *
 * Update a list of users returned by user_get_list
 *
 * @return value: G_OK on success, another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter j_user_list: The list of users returned by the user backend modules
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_get_list(struct config_module * config, json_t * j_user_list, void * cls);
```

```C
/**
 *
 * user_middleware_module_get
 *
 * Update a user returned by user_get
 *
 * @return value: G_OK on success, another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username corresponding to the j_user object
 * @parameter j_user: The user returned by the user backend module
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_get(struct config_module * config, const char * username, json_t * j_user, void * cls);
```

```C
/**
 *
 * user_middleware_module_get_profile
 *
 * Update a user returned by user_get_profile
 *
 * @return value: G_OK on success, another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username corresponding to the j_user object
 * @parameter j_user: The user returned by the user backend module
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_get_profile(struct config_module * config, const char * username, json_t * j_user, void * cls);
```

```C
/**
 *
 * user_middleware_module_update
 *
 * Update a user before being passed to the backend functions
 * user_module_add, user_module_update, user_module_update_profile
 * or user_module_is_valid
 *
 * @return value: G_OK on success, another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username corresponding to the j_user object
 * @parameter j_user: The user returned by the API
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls);
```

```C
/**
 *
 * user_middleware_module_delete
 * 
 * Update a user before being passed to the backend function user_module_delete
 *
 * @return value: G_OK on success, another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username corresponding to the j_user object
 * @parameter j_user: The user returned by the API
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_middleware_module_delete(struct config_module * config, const char * username, json_t * j_user, void * cls);
```

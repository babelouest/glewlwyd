# Glewlwyd Client Backend Modules

A Glewlwyd module is built as a library and loaded at startup. It must contain a specific set of functions available to glewlwyd to work properly.

A Glewlwyd module can access the entire data and functions available to Glewlwyd service. There is no limitation to its access. Therefore, Glewlwyd modules must be carefully designed and considered friendly. All data returned as `json_t *` or `char *` must be dynamically allocated, because they will be cleaned up by Glewlwyd after use.

Currently, the following client backend modules are available:
- [Database backend](database.c)
- [LDAP backend](ldap.c)

A client backend module is used to manage clients in a specific backend environment.
It is intended to:
- list clients
- get a specific client
- get a client profile data
- add a new client
- update a client
- delete a client
- verify a client password

A client is defined by attributes. The following attributes are mandatory for every client:

```javascript
{
  "client_id": string, identifies the client, must be unique
  "enabled": boolean, set this value to false will make the client unable to authenticate or do anything in Glewlwyd
  "confidential": boolean, in OAuth2 and OIDC plugins, confidential clients can be authorized
}
```

Other attributes can be added to a client, depending on the backend and the configuration. Any other attribute can be either a string or an array of strings. If another type is returned by the module, the behaviour is undefined.

Typically, the OAuth2 and OIDC plugins require the following attributes:

```javascript
{
  "authorization_type": array of strings, the following values are used: "code", "token", "id_token", "password", "client_credential", "refresh_token"
  "redirect_uri": array of strings, list of redirect uris allowed for this client
}
```

Other attributes are commonly used, example:

```javascript
{
  "name": string, display name for the client
  "description": string, description of the client
  "scope": array of strings, list of scopes available for the response type "client_credential"
}
```

A Glewlwyd module requires the library [Jansson](https://github.com/akheron/Jansson).

You can check out the existing modules for inspiration. You can start from the fake module [mock.c](mock.c) to build your own.

A pointer of `struct config_module` is passed to all the mandatory functions. This pointer gives access to some Glewlwyd data and some callback functions used to achieve specific actions.

The definition of the structure is the following:

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

A client module must have the following functions defined and available:

```C
/**
 * 
 * client_module_load
 * 
 * Executed once when Glewlwyd service is started
 * Used to identify the module and to show its parameters on init
 * You can also use it to load resources that are required once for all
 * instance modules for example
 * 
 * @return value: a json_t * value with the following pattern:
 * {
 *   result: number (G_OK on success, another value on error)
 *   name: string, mandatory, name of the module, must be unique among other scheme modules
 *   display_name: string, optional, long name of the module
 *   description: string, optional, description for the module
 *   parameters: object, optional, parameters description for the module
 * }
 * 
 * Example:
 * {
 *   result: G_OK,
 *   name: "mock",
 *   display_name: "Mock scheme module",
 *   description: "Mock scheme module for glewlwyd tests",
 *   parameters: {
 *     mock-value: {
 *       type: "string",
 *       mandatory: true
 *     }
 *   }
 * }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
json_t * client_module_load(struct config_module * config);
```

```C
/**
 * 
 * client_module_unload
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
int client_module_unload(struct config_module * config);
```

```C
/**
 * 
 * client_module_init
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
json_t * client_module_init(struct config_module * config, int readonly, json_t * j_parameters, void ** cls);
```

```C
/**
 * 
 * client_module_close
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
int client_module_close(struct config_module * config, void * cls);
```

```C
/**
 *
 * client_module_count_total
 *
 * Return the total number of clients handled by this module corresponding
 * to the given pattern
 *
 * @return value: The total of corresponding clients
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter pattern: The pattern to match for the clients. How the
 *                     pattern is used is up to the implementation.
 *                     Glewlwyd recommends to match the pattern with the
 *                     client_id, name and description value for each clients
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
size_t client_module_count_total(struct config_module * config, const char * pattern, void * cls);
```

```C
/**
 *
 * client_module_get_list
 *
 * Return a list of clients handled by this module corresponding
 * to the given pattern between the specified offset and limit
 * These are the client objects returned to the administrator
 *
 * @return value: A list of corresponding clients or an empty list
 *                using the following JSON format: {"result":G_OK,"list":[{client object}]}
 *                On error, this function must return another value for "result"
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter pattern: The pattern to match for the clients. How the
 *                     pattern is used is up to the implementation.
 *                     Glewlwyd recommends to match the pattern with the
 *                     client_id, name and description value for each clients
 * @pattern offset: The offset to reduce the returned list among the total list
 * @pattern limit: The maximum number of clients to return
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * client_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls);
```

```C
/**
 *
 * client_module_get
 *
 * Return a client object handled by this module corresponding
 * to the client_id specified
 *
 * @return value: G_OK and the corresponding client
 *                G_ERROR_NOT_FOUND if client_id is not found
 *                The returned format is {"result":G_OK,"client":{client object}}
 *                On error, this function must return another value for "result"
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter client_id: the client_id to match, must be case insensitive
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * client_module_get(struct config_module * config, const char * client_id, void * cls);
```

```C
/**
 *
 * client_module_is_valid
 *
 * Validate if a client is valid to save for the specified mode
 *
 * @return value: G_OK if the client is valid
 *                G_ERROR_PARAM and an array containing the errors in string format
 *                The returned format is {"result":G_OK} on success
 *                {"result":G_ERROR_PARAM,"error":["error 1","error 2"]} on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter client_id: the client_id to match, must be case insensitive
 * @parameter j_client: The client to validate
 * @parameter mode: The mode corresponding to the context, values available are:
 *                  - GLEWLWYD_IS_VALID_MODE_ADD: Add a client by an administrator
 *                    Note: in this mode, the module musn't check for already existing client,
 *                          This is already handled by Glewlwyd
 *                  - GLEWLWYD_IS_VALID_MODE_UPDATE: Update a client by an administrator
 * @parameter cls: pointer to the void * cls value allocated in client_module_init
 * 
 */
json_t * client_module_is_valid(struct config_module * config, const char * client_id, json_t * j_client, int mode, void * cls);
```

```C
/**
 *
 * client_module_add
 *
 * Add a new client by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter j_client: The client to add
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int client_module_add(struct config_module * config, json_t * j_client, void * cls);
```

```C
/**
 *
 * client_module_update
 *
 * Update an existing client by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter client_id: the client_id to match, must be case insensitive
 * @parameter j_client: The client to update. If this function must replace all values or 
 *                    only the given ones or any other solution is up to the implementation
 * @parameter cls: pointer to the void * cls value allocated in client_module_init
 * 
 */
int client_module_update(struct config_module * config, const char * client_id, json_t * j_client, void * cls);
```

```C
/**
 *
 * client_module_delete
 *
 * Delete an existing client by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter client_id: the client_id to match, must be case insensitive
 * @parameter cls: pointer to the void * cls value allocated in client_module_init
 * 
 */
int client_module_delete(struct config_module * config, const char * client_id, void * cls);
```

```C
/**
 *
 * client_module_check_password
 *
 * Validate the password of an existing client
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter client_id: the client_id to match, must be case insensitive
 * @parameter password: the password to validate
 * @parameter cls: pointer to the void * cls value allocated in client_module_init
 * 
 */
int client_module_check_password(struct config_module * config, const char * client_id, const char * password, void * cls);
```

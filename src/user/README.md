# Glewlwyd User Backend Modules

A Glewlwyd module is built as a library and loaded at startup. It must contain a specific set of functions available to glewlwyd to work properly.

A Glewlwyd module can access the entire data and functions available to Glewlwyd service. There is no limitation to its access. Therefore, Glewlwyd modules must be carefully designed and considered friendly. All data returned as `json_t *` or `char *` must be dynamically allocated, because they will be cleaned up by Glewlwyd after use.

Currently, the following user backend modules are available:
- [Database backend](database.c)
- [LDAP backend](ldap.c)
- [HTTP backend](http.c)

A user backend module is used to manage users in a specific backend environment.
It is intended to:
- list users
- get a specific user
- get a user profile data
- add a new user
- update a user
- delete a user
- verify a user password
- update a user password

A user is defined by attributes. The following attributes are mandatory for every user:

```javascript
{
  "username": string, identifies the user, must be unique
  "scope": array of string, list of scopes available to the user
  "enabled": boolean, set this value to false will make the user unable to authenticate or do anything in Glewlwyd
}
```

Other attributes can be added to a user, depending on the backend and the configuration. Any other attribute can be either a string or an array of strings. If another type is returned by the module, the behaviour is undefined.

Glewlwyd uses two other attributes if they are returned by the module: `email` and `name`.

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

A user module must have the following functions defined and available:

```C
/**
 * 
 * user_module_load
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
json_t * user_module_load(struct config_module * config);
```

```C
/**
 * 
 * user_module_unload
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
int user_module_unload(struct config_module * config);
```

```C
/**
 * 
 * user_module_init
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
json_t * user_module_init(struct config_module * config, int readonly, json_t * j_parameters, void ** cls);
```

```C
/**
 * 
 * user_module_close
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
int user_module_close(struct config_module * config, void * cls);
```

```C
/**
 *
 * user_module_count_total
 *
 * Return the total number of users handled by this module corresponding
 * to the given pattern
 *
 * @return value: The total of corresponding users
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter pattern: The pattern to match for the users. How the
 *                     pattern is used is up to the implementation.
 *                     Glewlwyd recommends to match the pattern with the
 *                     username, name and e-mail value for each users
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
size_t user_module_count_total(struct config_module * config, const char * pattern, void * cls);
```

```C
/**
 *
 * user_module_get_list
 *
 * Return a list of users handled by this module corresponding
 * to the given pattern between the specified offset and limit
 * These are the user objects returned to the administrator
 *
 * @return value: A list of corresponding users or an empty list
 *                using the following JSON format: {"result":G_OK,"list":[{user object}]}
 *                On error, this function must return another value for "result"
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter pattern: The pattern to match for the users. How the
 *                     pattern is used is up to the implementation.
 *                     Glewlwyd recommends to match the pattern with the
 *                     username, name and e-mail value for each users
 * @pattern offset: The offset to reduce the returned list among the total list
 * @pattern limit: The maximum number of users to return
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * user_module_get_list(struct config_module * config, const char * pattern, size_t offset, size_t limit, void * cls);
```

```C
/**
 *
 * user_module_get
 *
 * Return a user object handled by this module corresponding
 * to the username specified
 * This is the user object returned to the administrator
 *
 * @return value: G_OK and the corresponding user
 *                G_ERROR_NOT_FOUND if username is not found
 *                The returned format is {"result":G_OK,"user":{user object}}
 *                On error, this function must return another value for "result"
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * user_module_get(struct config_module * config, const char * username, void * cls);
```

```C
/**
 *
 * user_module_get_profile
 *
 * Return a user object handled by this module corresponding
 * to the username specified.
 * This is the user object returned to the connected user, may be different from the 
 * user_module_get object format if a connected user must have access to different data
 *
 * @return value: G_OK and the corresponding user
 *                G_ERROR_NOT_FOUND if username is not found
 *                The returned format is {"result":G_OK,"user":{user object}}
 *                On error, this function must return another value for "result"
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * user_module_get_profile(struct config_module * config, const char * username, void * cls);
```

```C
/**
 *
 * user_module_is_valid
 *
 * Validate if a user is valid to be saved for the specified mode
 *
 * @return value: G_OK if the user is valid
 *                G_ERROR_PARAM and an array containing the errors in string format
 *                The returned format is {"result":G_OK} on success
 *                {"result":G_ERROR_PARAM,"error":["error 1","error 2"]} on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter j_user: The user to validate
 * @parameter mode: The mode corresponding to the context, values available are:
 *                  - GLEWLWYD_IS_VALID_MODE_ADD: Add a user by an administrator
 *                    Note: in this mode, the module musn't check for already existing user,
 *                          This is already handled by Glewlwyd
 *                  - GLEWLWYD_IS_VALID_MODE_UPDATE: Update a user by an administrator
 *                  - GLEWLWYD_IS_VALID_MODE_UPDATE_PROFILE: Update a user by him or 
 *                                                           herself in the profile context
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
json_t * user_module_is_valid(struct config_module * config, const char * username, json_t * j_user, int mode, void * cls);
```

```C
/**
 *
 * user_module_add
 *
 * Add a new user by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter j_user: The user to add
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_add(struct config_module * config, json_t * j_user, void * cls);
```

```C
/**
 *
 * user_module_update
 *
 * Update an existing user by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter j_user: The user to update. If this function must replace all values or 
 *                    only the given ones or any other solution is up to the implementation
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls);
```

```C
/**
 *
 * user_module_update_profile
 *
 * Update an existing user in the profile context
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter j_user: The user to update. If this function must replace all values or 
 *                    only the given ones or any other solution is up to the implementation
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_update_profile(struct config_module * config, const char * username, json_t * j_user, void * cls);
```

```C

/**
 *
 * user_module_delete
 *
 * Delete an existing user by an administrator
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_delete(struct config_module * config, const char * username, void * cls);
```

```C
/**
 *
 * user_module_check_password
 *
 * Validate the password of an existing user
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter password: the password to validate
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_check_password(struct config_module * config, const char * username, const char * password, void * cls);
```

```C
/**
 *
 * user_module_update_password
 *
 * Update the password only of an existing user
 *
 * @return value: G_OK on success
 *                Another value on error
 *
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: the username to match, must be case insensitive
 * @parameter new_password: the new password
 * @parameter cls: pointer to the void * cls value allocated in user_module_init
 * 
 */
int user_module_update_password(struct config_module * config, const char * username, const char * new_password, void * cls);
```

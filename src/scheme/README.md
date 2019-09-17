# Glewlwyd Authentication Scheme Modules

A Glewlwyd module is built as a library and loaded at startup. It must contain a specific set of functions available to glewlwyd to work properly.

A Glewlwyd module can access the entire data and functions available to Glewlwyd service. There is no limitation to its access. Therefore, Glewlwyd modules must be carefully designed and considered friendly. All data returned as `json_t *` or `char *` must be dynamically allocated, because they will be cleaned up by Glewlwyd after use.

An authentication scheme module is independent from the user backends. The scheme module can use the user attributes to get or update data for its own purpose, or it can use a dedicated data storage.

Currently, the following schemes are available:
- [Random code sent by e-mail](email.c)
- [HOTP/TOTP](otp.c)
- [Webauthn](webauthn.c)
- [Short session password](password.c)
- [TLS Certificate](certificate.c)

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

A authentication scheme module must have the following functions defined and available:

```C
/**
 * 
 * user_auth_scheme_module_load
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
json_t * user_auth_scheme_module_load(struct config_module * config);
```

```C
/**
 * 
 * user_auth_scheme_module_unload
 * 
 * Executed once when Glewlwyd service is stopped
 * You can also use it to release resources that are required once for all
 * instance modules for example
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
int user_auth_scheme_module_unload(struct config_module * config);
```

```C
/**
 * 
 * user_auth_scheme_module_init
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
 * @parameter mod_name: module name in glewlwyd service
 * @parameter cls: will contain an allocated void * pointer that will be sent back
 *                 as void * in all module functions
 * 
 */
json_t * user_auth_scheme_module_init(struct config_module * config, json_t * j_parameters, const char * mod_name, void ** cls);
```

```C
/**
 * 
 * user_auth_scheme_module_close
 * 
 * Close an instance of this module declared in Glewlwyd service.
 * You must free the memory previously allocated in
 * the user_auth_scheme_module_init function as void * cls
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_close(struct config_module * config, void * cls);
```

```C
/**
 * 
 * user_auth_scheme_module_can_use
 * 
 * Validate if the user is allowed to use this scheme prior to the
 * authentication or registration
 * 
 * @return value: GLEWLWYD_IS_REGISTERED - User can use scheme and has registered
 *                GLEWLWYD_IS_AVAILABLE - User can use scheme but hasn't registered
 *                GLEWLWYD_IS_NOT_AVAILABLE - User can't use scheme
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: username to identify the user
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_can_use(struct config_module * config, const char * username, void * cls);
```

```C
/**
 * 
 * user_auth_scheme_module_register
 * 
 * Register the scheme for a user
 * Ex: add a certificate, add new TOTP values, etc.
 * 
 * @return value: a json_t * value with the following pattern:
 * {
 *   result: number (G_OK on success, another value on error)
 *   response: JSON object, optional
 * }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the HTTP API
 * @parameter username: username to identify the user
 * @parameter j_scheme_data: additional data used to register the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_register(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls);
```

```C
/**
 * 
 * user_auth_scheme_module_register_get
 * 
 * Get the registration value(s) of the scheme for a user
 * 
 * @return value: a json_t * value with the following pattern:
 * {
 *   result: number (G_OK on success, another value on error)
 *   response: JSON object, optional
 * }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_register_get(struct config_module * config, const struct _u_request * http_request, const char * username, void * cls);
```

```C
/**
 * 
 * user_auth_scheme_module_trigger
 * 
 * Trigger the scheme for a user
 * Ex: send the code to a device, generate a challenge, etc.
 * 
 * @return value: a json_t * value with the following pattern:
 * {
 *   result: number (G_OK on success, another value on error)
 *   response: JSON object, optional
 * }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter scheme_trigger: data sent to trigger the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_trigger(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_trigger, void * cls);
```

```C
/**
 * 
 * user_auth_scheme_module_validate
 * 
 * Validate the scheme for a user
 * Ex: check the code sent to a device, verify the challenge, etc.
 * 
 * @return value: G_OK on success
 *                G_ERROR_UNAUTHORIZED if validation fails
 *                G_ERROR_PARAM if error in parameters
 *                G_ERROR on another error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter j_scheme_data: data sent to validate the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_validate(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls);
```

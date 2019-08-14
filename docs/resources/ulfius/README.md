# Token validation for resource service based on [Ulfius](https://github.com/babelouest/ulfius) framework

These files contain an authentication callback for Ulfius framework to validate a Glewlwyd access token or OIDC access tokens with the correct scope.

[ulfius](https://github.com/babelouest/ulfius), [libjwt](https://github.com/benmcollins/libjwt) and [jansson](https://github.com/akheron/jansson) are required.

## Validate Glewlwyd OAuth2 access token

The provided files are `glewlwyd_resource.h` and `glewlwyd_resource.c`. The Ulfius callback function is:

```C
/**
 * 
 * check if bearer token has some of the specified scope
 * 
 */
int callback_check_glewlwyd_access_token (const struct _u_request * request, struct _u_response * response, void * user_data);
```

To use this file, you must create a `struct _glewlwyd_resource_config` with your specific parameters:

```C
struct _glewlwyd_resource_config {
  int            method;              // Values are G_METHOD_HEADER, G_METHOD_BODY or G_METHOD_URL for the access_token location, see https://tools.ietf.org/html/rfc6750
  char *         oauth_scope;         // Scope values required by the resource, multiple values must be separated by a space character
  char *         jwt_decode_key;      // The key used to decode an access token
  jwt_alg_t      jwt_alg;             // The algorithm used to encode a token, see http://benmcollins.github.io/libjwt/
  char *         realm;               // Optional, a realm value that will be sent back to the client
  unsigned short accept_access_token; // required, accept type access_token
  unsigned short accept_client_token; // required, accept type client_token
};
```

Then, you use `callback_check_glewlwyd_access_token` as authentication callback for your ulfius endpoints that need to validate a glewlwyd access_token, example:

```C
struct _glewlwyd_resource_config g_config;
g_config.method = G_METHOD_HEADER;
g_config.oauth_scope = "scope1";
g_config.jwt_decode_key = "secret";
g_config.jwt_alg = JWT_ALG_HS512;
g_config.realm = "example";
g_config.accept_access_token = 1;
g_config.accept_client_token = 0;

// Example, add an authentication callback callback_check_glewlwyd_access_token for the endpoint GET "/api/resource/*"
ulfius_add_endpoint_by_val(instance, "GET", "/api", "/resource/*", &callback_check_glewlwyd_access_token, (void*)&g_config);
```

On success, the variable `response->shared_data` will be provided with a `json_t *` objet with the following format:

```Javascript
{
  "username": "user",         // username whose grant access is granted
  "scope":["scope1","scope2"] // Scope list the user is granted for this access token
}
```

On error, the next callback function will not be called and instead, the client will receive an error 401 with the header `WWW-Authenticate` filled with the error.

## Validate Glewlwyd OpenID Connect access token

The provided files are `oidc_resource.h` and `oidc_resource.c`. The Ulfius callback function is:

```C
/**
 * 
 * check if bearer token has some of the specified scope
 * 
 */
int callback_check_glewlwyd_oidc_access_token (const struct _u_request * request, struct _u_response * response, void * user_data);
```

To use this file, you must create a `struct _oidc_resource_config` with your specific parameters:

```C
struct _oidc_resource_config {
  int            method;              // Values are G_METHOD_HEADER, G_METHOD_BODY or G_METHOD_URL for the access_token location, see https://tools.ietf.org/html/rfc6750
  char *         oauth_scope;         // Scope values required by the resource, multiple values must be separated by a space character
  char *         jwt_decode_key;      // The key used to decode an access token
  jwt_alg_t      jwt_alg;             // The algorithm used to encode a token, see http://benmcollins.github.io/libjwt/
  char *         realm;               // Optional, a realm value that will be sent back to the client
  unsigned short accept_access_token; // required, accept type access_token
  unsigned short accept_client_token; // required, accept type client_token
};
```

Then, you use `callback_check_glewlwyd_oidc_access_token` as authentication callback for your ulfius endpoints that need to validate a glewlwyd access_token, example:

```C
struct _oidc_resource_config g_config;
g_config.method = G_METHOD_HEADER;
g_config.oauth_scope = "scope1";
g_config.jwt_decode_key = "secret";
g_config.jwt_alg = JWT_ALG_HS512;
g_config.realm = "example";
g_config.accept_access_token = 1;
g_config.accept_client_token = 0;

// Example, add an authentication callback callback_check_glewlwyd_oidc_access_token for the endpoint GET "/api/resource/*"
ulfius_add_endpoint_by_val(instance, "GET", "/api", "/resource/*", &callback_check_glewlwyd_oidc_access_token, (void*)&g_config);
```

On success, the variable `response->shared_data` will be provided with a `json_t *` objet with the following format:

```Javascript
{
  "sub": "user",              // subject this grant access is granted for
  "aud": "client1",           // client this grant access is granted to
  "scope":["scope1","scope2"] // Scope list the user is granted for this access token
}
```

On error, the next callback function will not be called and instead, the client will receive an error 401 with the header `WWW-Authenticate` filled with the error.

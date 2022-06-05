# Token validation for resource service based on [Ulfius](https://github.com/babelouest/ulfius) framework

These files contain an authentication callback for Ulfius framework to validate a Glewlwyd access token or OIDC access tokens with the correct scope.

## Validate Glewlwyd OpenID Connect access token

[ulfius](https://github.com/babelouest/ulfius), [rhonabwy](https://github.com/babelouest/rhonabwy), [iddawc](https://github.com/babelouest/iddawc) and [jansson](https://github.com/akheron/jansson) are required.

The provided files are `iddawc_resource.h` and `iddawc_resource.c`. The Ulfius callback function is:

```C
int callback_check_jwt_profile_access_token (const struct _u_request * request, struct _u_response * response, void * user_data);
```

To use this callback function, you must initialize a `struct _iddawc_resource_config` with your specific parameters:

```C
#define I_METHOD_HEADER 0
#define I_METHOD_BODY   1
#define I_METHOD_URL    2

int i_jwt_profile_access_token_init_config(struct _iddawc_resource_config * config, unsigned short method, const char * realm, const char * aud, const char * oauth_scope, const char * resource_url_root, time_t dpop_max_iat);

// Use this function to configure the struct _iddawc_resource_config * with a remote openid configuration url
int i_jwt_profile_access_token_load_config(struct _iddawc_resource_config * config, const char * config_url, int verify_cert);

// Use this function to configure the struct _iddawc_resource_config * with a specified public key JWKS and an issuer
int i_jwt_profile_access_token_load_jwks(struct _iddawc_resource_config * config, json_t * j_jwks, const char * iss);

// At the end of the program, to clean the struct _iddawc_resource_config *
void i_jwt_profile_access_token_close_config(struct _iddawc_resource_config * config);
```

Then, you use `callback_check_jwt_profile_access_token` as authentication callback for your ulfius endpoints that need to validate a glewlwyd access_token. The callback function will also validate a `DPoP` token if present.

On success, the variable `response->shared_data` will be provided with a `json_t *` objet with the full access token payload:

On error, the next callback function will not be called and instead, the client will receive an error 401 with the header `WWW-Authenticate` filled with the error.

## Validate Glewlwyd OAuth2 access token

[ulfius](https://github.com/babelouest/ulfius), [rhonabwy](https://github.com/babelouest/rhonabwy) and [jansson](https://github.com/akheron/jansson) are required.

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
  jwt_t *        jwt;                 // The jwt used to decode and validate an access token
  jwa_alg        alg;                 // The algorithm used to encode a token, see https://babelouest.github.io/rhonabwy/
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
r_jwt_init(&g_config.jwt);
r_jwt_set_sign_alg(g_config.jwt, R_JWA_ALG_HS256);
r_jwt_add_sign_key_symmetric(g_config.jwt, "secret", o_strlen("secret")
g_config.alg = R_JWA_ALG_HS256;
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

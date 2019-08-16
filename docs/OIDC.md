# Glewlwyd OpenID Connect Plugin documentation

This plugin is based on the [OpenID Connect Core 1.0 specification](https://openid.net/specs/openid-connect-core-1_0.html) and allows Glewlwyd to act as an OpenID Provider (OP).

## Functionalities summary

The following OpenID Connect Core functionalities are currently supported:

- [Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
- [Implicit flow](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth)
- [Hybrid flow](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth)
- [UserInfo Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
- [OAuth 2.0 Multiple Response Types](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
- [OpenID Connect Discovery](http://openid.net/specs/openid-connect-discovery-1_0.html)
- [Address Claims](https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim)
- [Requesting Claims using the "claims" Request Parameter](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)
- [Client authentication](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) using HTTP Basic Auth, POST Parameter or signed JWT
- [Passing Request Parameters as JWTs](https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests)
- [Subject Types public or pairwise](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes)

The following OpenID Connect Core functionalities are not supported yet:

- [Client authentification with JWT](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
- [Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
- [Claims Languages and Scripts](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsLanguagesAndScripts)
- [Self-Issued OpenID Provider](https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued)
- [id_token encryption](https://openid.net/specs/openid-connect-core-1_0.html#Encryption)

The following OpenID Connect specifications are not supported yet:

- [OpenID Connect Dynamic Registration](http://openid.net/specs/openid-connect-registration-1_0.html)
- [OAuth 2.0 Form Post Response Mode](http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)

## Access token format

As a heir of [Glewlwyd OAuth2 plugin](OAUTH2.md), Glewlwyd OpenID Connect plugin uses JWTs as access tokens. Therefore, the access token can be used by the client or the third party web service to identify the user and the scopes available with this access token.

An access token payload has the following JSON format:

```Javascript
{
  "sub": "user1",            // subject that was provided this access_token
  "aud": "client1",          // client_id the access_token was provided to
  "salt": "abcdxyz1234",     // Random string to avoid collisions
  "type": "access_token",    // Hardcoded
  "iat": 1466556840,         // Issued at time in Epoch Unix format
  "exp": 1466558840,         // Expiration of the token in Epoch Unix format
  "scope":"scope1 g_profile" // scopes granted to this access token in a string separated by spaces
}
```

## Installation

![plugin-oidc](screenshots/plugin-oidc.png)

In the administration page, go to `Parameters/Plugins` and add a new plugin by clicking on the `+` button. In the modal, enter a name and a display name (the name must be unique among all user backend instances).
Select the type `Glewlwyd OpenID Connect Plugin` in the Type dropdown button.

Below is the definition of all parameters.

### Name

Name (identifier) of the plugin instance, must be unique among all the plugin instances, even of a different type.

### Display name

Name of the instance displayed to the user.

### Issuer

Issuer that will be added in all ID Tokens, must correspond to your Glewlwyd instance URL.

### Allow passing request parameter as JWT

Allow using request parameters as JWT with `request` objects or `request_uri` links.

### Allow request_uri to a unsecure https:// uri

If the specified `request_uri` link points to an unsecure https:// page with invalid certificate or hostname, allow it anyway.

Warning! This may lead to unsecure connections or MITM attacks.

### Subject type identifier

Specify the way to identify subjects.

If the selected value is `public`, the `sub` value in access tokens and id tokens will always have the same value.

If the selected value is `pairwise`, the `sub` value in access tokens and id tokens will have a different values for clients of differents `sector_identifier_uri` or if the `sector_identifier_uri` is empty, for different clients.

### JWT Type

Algorithm used to sign access tokens and ID Tokens.

The algorithm supported are `RSA` and `ECDSA` using a private and a public key, and `SHA` using a shared secret.

### Key size

Size of the key to sign the tokens. The sizes supported are 256 bits, 384 bits or 512 bits.

### Secret key

Private key file used to sign if the selected algorithm is `RSA` or `ECDSA`. Must be an X509 PEM file.
Shared secret if the selected algorithm is `SHA`.

### Public key

Public certificate file used to validate access tokens if the selected algorithm is `RSA` or `ECDSA`. Must be an X509 PEM file.

### Access token duration (seconds)

Duration of each access tokens. Default value is 3600 (1 hour).

### Refresh token duration (seconds)

Duration of validity of each refresh tokens. Default value is 1209600 (14 days).

### Code duration (seconds)

Duration of validity of each code sent to the client befire requesting a refresh token. Default value is 600 (10 minutes).

### Refresh token rolling

If this option is checked, every time an access token is requested using a refresh token, the refresh token issued at time will be reset to the current time. This option allows infinite validity for the refresh tokens if it's not manually disabled, but if a refresh token isn't used for more of the value `Refresh token duration`, it will be disabled.

### Allow non OIDC but valid OAuth2 requests

If this option is checked, the plugin instance will allow requests that are not allowed in the OIDC standard but valid in the OAuth2 standard, such as response_type: `token` (alone), `password` or `client_credential`. In those cases, the request will be trated as a normal OAuth2 but the response will not have an ID Token.

### Authentication type code enabled

Enable response type `code`.

### Authentication type token enabled

Enable response type `token`.

### Authentication type ID Token enabled

This option is enabled and can't be disabled.

### Authentication type password enabled

Enable response type `password`.

### Authentication type client enabled

Enable response type `client_credential`.

### Authentication type refresh enabled

Enable response type `refresh_token`.

### Service documentation URL (optional)

`openid-configuration` URL to the service documentation to help users or client to connect to Glewlwyd server, default is Glewlwyd GitHub documentation.

### Service policy URL (optional)

`openid-configuration` URL to the service policy.

### Terms of service URL (optional)

`openid-configuration` URL to the terms of service.

### JWKS available

Enable JWKS available at the address `<plugin_root>/jwks`. Note, JWKS is available for key types `RSA` and `ECDSA` only.

### X5C certificate chain (optional)

Add or remove the chain of X5C certificate to help clients and users validate the certificate chain of each `id_token` or `access_token`.

### Specific scope parameters

This section allows to put specific settings for an scope that will override the plugin settings.

The settings that you can override are `Refresh token duration` and/or `Rolling refresh`.

Please note that a specific scope parameter has a higher priority than the plugin settings, and if have multiple scopes in a request that have specific settings, the settings will follow the following algorithm:
- Refresh token duration: The duration provided will be the lowest duration among all the specific scope parameters.
- Roling refresh: The value `No`has higher priority, therefore rolling refresh provided will be `No` if one scope has the value `No`, `Yes` otherwise

### Additional token values

This section allows to add specific values to the access_tokens that will be taken from the user property values.

You can add as many additional values as you want. If the property isn't present in the user data, it will be ignored. If the value is mutiple, all values will be present, separated by a comma `,`.

### Additional parameters in the ID Token or the /userinfo endpoint

This section allows to add specific claims in ID Tokens or userinfo results.

If you specify a type `number`, the value will be converted from a string to an integer.

If the conversion fails, the value will be ignored. If you specify a type `boolean`, you must specify the values for `true` and `false`. If the value doesn't match, it will be ignored.

If you check the option `Mandatory`, the claim will be added in all ID Tokens or userinfo calls, even if the claim isn't requested by the user.

## Client secret vs password

When you add or edit a client in Glewlwyd, you can set a `client secret` or a `password`. Both can be used to authenticate confidential clients.

The primary difference is that a client secret is a string stored 'as is' in the backend (database or LDAP), without hashing, where a client password is stored in a hashed form in the backend, so makes it more difficult for attackers to retrieve it.

A client secret has priority over a client password, which means that if a client has set both client secret and client password, the authentication will be executed with client secret only.

The `client secret` can also be used to authenticate a client using the method `sclient_secret_jwt` when it will be available.

## Glewlwyd OpenID Connect endpoints specifications

This document is intended to describe Glewlwyd OpenID Connect plugin implementation.

OpenID Connect endpoints are used to authenticate the user, and to send tokens, id_tokens or other authentication and identification data. The complete specification is available in the [OpenID Connect Core](http://openid.net/specs/openid-connect-core-1_0.html). If you see an issue or have a question on Glewlwyd OpenID Connect plugin implementation, you can open an issue or send an email to the following address [mail@babelouest.org](mailto:mail@babelouest.org).

- [Endpoints authentication](#endpoints-authentication)
- [Prefix](#prefix)
- [Login and grant URIs](#login-and-grant-uris)
- [Scope](#scope)
- [OpenID Connect endpoints](#openid-connect-endpoints)
  - [Authorization endpoint](#authorization-endpoint)
  - [Token endpoint](#token-endpoint)
- [OpenID Connect schemes](#openid-connect-schemes)
  - [Authorization code grant - Authorization request](#authorization-code-grant---authorization-request)
  - [Authorization code grant - Authorization Response](#authorization-code-grant---authorization-response)
  - [Implicit Grant](#implicit-grant)
  - [ID Token Grant](#id-token-grant)
  - [Resource Owner Password Credentials Grant](#resource-owner-password-credentials-grant)
  - [Client Credentials Grant](#client-credentials-grant)
  - [Refresh token](#refresh-token)
  - [Invalidate refresh token](#invalidate-refresh-token)
- [Userinfo endpoint](#userinfo-endpoint)
- [openid-configuration endpoint](#openid-configuration-endpoint)
- [Get JSON Web Key](#get-json-web-key)
- [Manage refresh tokens endpoints](#manage-refresh-tokens-endpoints)
  - [List refresh tokens](#list-refresh-tokens)
  - [Disable a refresh token by its signature](#disable-a-refresh-token-by-its-signature)

### Endpoints authentication

Authentication has different faces, and differs with the authorization scheme.

### Prefix

All URIs are based on the prefix you will setup. In this document, all API endpoints will assume they use the prefix `/api/oidc`, and all static file endpoints will assume they use the prefix `/`.

### Login and grant URIs

In this document, the login URI will be displayed as `http://login.html`, this will be replaced by the values from your environment that you can define in the config file.

### OpenID Connect endpoints

#### Authorization endpoint

This is a multi-method, multi-parameters, versatile endpoint, used to provide authentication management. It handles the following authorization schemes as describe in the [OpenID Connect Core](http://openid.net/specs/openid-connect-core-1_0.html):

- Authorization Code Grant (Authorization part)
- Implicit Grant
- Hybrid Grant

##### URL

`/api/oidc/auth`

##### Method

`GET`
`POST`

#### Token endpoint

This endpoint is used to provide tokens to the user. It handles the following authorization schemes as describe in the [OpenID Connect Core](http://openid.net/specs/openid-connect-core-1_0.html):

- Authorization Code Grant (Access Token part)
- ID Token Grant
- Resource Owner Password Credentials Grant (if enabled)
- Client Credentials Grant (if enabled)
- Refreshing a token
- Deleting a token

##### URL

`/api/oidc/token`

##### Method

`POST`

### OAuth 2 schemes

Each scheme is described in the following chapter. The description may not be as complete as the [OAuth 2 RFC document](https://tools.ietf.org/html/rfc6749), consider the RFC as the authority standard.

#### Authorization code grant - Authorization request

##### URL

`/api/oidc/auth`

##### Method

`GET`
`POST`

##### URL (GET) or body (POST) Parameters

Required

```
`response_type`: text, must be set to `code`
`client_id`: text, client_id that sends the request on behalf of the resource owner, must be a valid client_id
`redirect_uri`: text, redirect_uri to send the resource owner to after the connection, must be a valid redirect_uri for the specified client_id
`scope`: text, scope list that the resource owner will grant access to the client, multiple scope values must be separated by a space, scope `openid` is mandatory in an OpenID Connect request
`nonce`: text, recommended for response type code, mandatory for all other response types
```

Optional

`state`: text, an identifier used to prevent requests collisions and bypass, will be sent back as is to the client

##### Result

###### Resource owner not authenticated

Code 302

Resource owner is not authenticated with a valid session.

Redirect to `http://login.html?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&additional_parameters` for authentication.

See login paragraph for details.

###### Scope not granted to the client

Code 302

Redirect to `http://login.html?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&additional_parameters` for grant access.

###### Success response

Code 302

Redirect to `redirect_uri`?code=`code`&state=`state`

with `redirect_uri` specified in the request, a `code` generated for the access, and the state specified in the request if any.

###### Error Scope

Scope is not allowed for this user

Code 302

Redirect to `redirect_uri`?error=invalid_scope&state=`state`

with `redirect_uri` specified in the request, `invalid_scope` as error value, and the state specified in the request if any.

###### Error client

Client is invalid, redirect_uri is invalid for this client, or client is not allowed to use this scheme

Code 302

Redirect to `redirect_uri`?error=unauthorized_client&state=`state`

with `redirect_uri` specified in the request, `unauthorized_client` as error value, and the state specified in the request if any.

#### Authorization code grant - Authorization Response

##### URL

`/api/oidc/token`

##### Method

`POST`

##### Security

If `client_id` refers to a confidential client, then client_id and client_password must be sent via Basic HTTP Auth.

##### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "authorization_code".
code: text, required
redirect_uri: text, must be same redirect_uri used in the authorization request that sent back this code
client_id: text, must be the same client_id used in the authorization request that sent back this code
```

##### Success response

Code 200

Content

```javascript
{
  "access_token":text, jwt token
  "token_type":text, value is "bearer",
  "expires_in":number, set by server configuration
  "refresh_token":text,
  "id_token": text, jwt token
}
```

##### Error Response

Code 400

Error input parameters

The combination code/redirect_uri/client_id is incorrect.

#### Implicit Grant

##### URL

`/api/oidc/auth`

##### Method

`GET`

##### URL Parameters

Required

```
`response_type`: text, must be set to `token`
`client_id`: text, client_id that sends the request on behalf of the resource owner, must be a valid client_id
`redirect_uri`: text, redirect_uri to send the resource owner to after the connection, must be a valid redirect_uri for the specified client_id
`scope`: text, scope list that the resource owner will grant access to the client, multiple scope values must be separated by a space
```

Optional

`state`: text, an identifier used to prevent requests collisions and bypass, will be sent back as is to the client

##### Result

###### Resource owner not authenticated

Code 302

Resource owner is not authenticated with a valid session.

Redirect to `http://login.html?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&additional_parameters` for authentication.

See login paragraph for details.

###### Scope not granted to the client

Code 302

Redirect to `http://grant.html?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&additional_parameters` for grant access.

See grant paragraph for details.

###### Success response

Code 302

Redirect to `redirect_uri`#token=`token`&state=`state`

with `redirect_uri` specified in the request, a `code` generated for the access, and the state specified in the request if any.

###### Error Scope

Scope is not allowed for this user

Code 302

Redirect to `redirect_uri`#error=invalid_scope&state=`state`

with `redirect_uri` specified in the request, `invalid_scope` as error value, and the state specified in the request if any.

###### Error client

Client is invalid, redirect_uri is invalid for this client, or client is not allowed to use this scheme

Code 302

Redirect to `redirect_uri`#error=unauthorized_client&state=`state`

with `redirect_uri` specified in the request, `unauthorized_client` as error value, and the state specified in the request if any.

#### ID Token Grant

##### URL

`/api/oidc/auth`

##### Method

`GET`

##### URL Parameters

Required

```
`response_type`: text, must be set to `id_token`
`client_id`: text, client_id that sends the request on behalf of the resource owner, must be a valid client_id
`redirect_uri`: text, redirect_uri to send the resource owner to after the connection, must be a valid redirect_uri for the specified client_id
`scope`: text, scope list that the resource owner will grant access to the client, multiple scope values must be separated by a space
`nonce`: text, nonce value generated by the client, mandatory
```

Optional

`state`: text, an identifier used to prevent requests collisions and bypass, will be sent back as is to the client

##### Result

###### Resource owner not authenticated

Code 302

Resource owner is not authenticated with a valid session.

Redirect to `http://login.html?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&additional_parameters` for authentication.

See login paragraph for details.

###### Scope not granted to the client

Code 302

Redirect to `http://login.html?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&additional_parameters` for grant access.

See grant paragraph for details.

###### Success response

Code 302

Redirect to `redirect_uri`#id_token=`token`&state=`state`

with `redirect_uri` specified in the request, a `code` generated for the access, and the state specified in the request if any.

###### Error Scope

Scope is not allowed for this user

Code 302

Redirect to `redirect_uri`#error=invalid_scope&state=`state`

with `redirect_uri` specified in the request, `invalid_scope` as error value, and the state specified in the request if any.

###### Error client

Client is invalid, redirect_uri is invalid for this client, or client is not allowed to use this scheme

Code 302

Redirect to `redirect_uri`#error=unauthorized_client&state=`state`

with `redirect_uri` specified in the request, `unauthorized_client` as error value, and the state specified in the request if any.

#### Resource Owner Password Credentials Grant

##### URL

`/api/oidc/token`

##### Method

`POST`

##### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "password".
username: text
password: text
scope: text
```

##### Success response

Code 200

Content

```javascript
{
  "access_token":text, jwt token
  "token_type":text, value is "bearer",
  "expires_in":number, set by server configuration
  "refresh_token":text, jwt token
}
```

##### Error Response

Code 403

username or password invalid.

#### Client Credentials Grant

##### URL

`/api/oidc/token`

##### Method

`POST`

##### Security

HTTP Basic authentication with client_id/client_password credentials. Client_id must be set as confidential

##### URL Parameters

Required

Optional

##### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "client_credentials".
scope: text
```

##### Success response

Code 200

Content

```javascript
{
  "access_token":text, jwt token
  "token_type":text, value is "bearer",
  "expires_in":number, set by server configuration
}
```

##### Error Response

Code 403

Access denied

#### Refresh token

Send a new access_token based on a valid refresh_token

##### URL

`/api/oidc/token`

##### Method

`POST`

##### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "refresh_token".
refresh_token: text, a valid ref refresh_token, mandatory
scope: text, must the same scope or a sub scope of the scope used to provide the refresh_token, optional
```

##### Success response

Code 200

Content

```javascript
{
  "access_token":text, jwt token
  "token_type":text, value is "bearer",
  "expires_in":number, set by server configuration
}
```

##### Error Response

Code 400

Error input parameters

#### Invalidate refresh token

Mark a refresh_token as invalid, to prevent further access_token to be generated

##### URL

`/api/oidc/token`

##### Method

`POST`

##### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "delete_token".
refresh_token: text, a valid refresh_token, mandatory
```

##### Success response

Code 200

##### Error Response

Code 400

Error input parameters

### Userinfo endpoint

This endpoint is defined in the OpenID Connect core: [Userinfo Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo). It's used to get information about a user in JSON format. Default information are displayed, and additional claims can be requested.

#### URL

`/api/oidc/unserinfo`

#### Method

`GET`

#### Security

A valid access token is required to access tis endpoint. The user shown in this endpoint result will be the one the access token was created for.

#### URL Parameters

Optional

```
`claims`: text, list of additional claims separated by space
```

##### Result

##### Success response

Code 200

Content

```javascript
{
  "sub": text, subject of the endpoint (user)
  "name": text, name of the user
  "email": text, email of the user
}
```

##### Error Response

Code 403

Access denied

### openid-configuration endpoint

This endpoint implements the [OpenID Connect discovery](http://openid.net/specs/openid-connect-discovery-1_0.html) API.

#### URL

`/api/oidc/.well-known/openid-configuration`

#### Method

`GET`

##### Result

##### Success response

Code 200

Content

`openid-configuration` content in JSON format.

Example:

```javascript
{
   "issuer":"https://glewlwyd.tld",
   "authorization_endpoint":"http://localhost:4593/api/oidc/auth",
   "token_endpoint":"http://localhost:4593/api/oidc/token",
   "userinfo_endpoint":"http://localhost:4593/api/oidc/userinfo",
   "jwks_uri":"http://localhost:4593/api/oidc/jwks",
   "token_endpoint_auth_methods_supported":[
      "client_secret_basic"
   ],
   "token_endpoint_auth_signing_alg_values_supported":[
      "HS256"
   ],
   "scopes_supported":[
      "openid"
   ],
   "response_types_supported":[
      "code",
      "id_token",
      "token id_token",
      "code id_token",
      "code token id_token",
      "none",
      "password",
      "token",
      "client_credentials",
      "refresh_token"
   ],
   "response_modes_supported":[
      "query",
      "fragment"
   ],
   "grant_types_supported":[
      "authorization_code",
      "implicit"
   ],
   "display_values_supported":[
      "page",
      "touch",
      "wap"
   ],
   "claim_types_supported":[
      "normal"
   ],
   "claims_supported":[

   ],
   "ui_locales_supported":[
      "en",
      "fr"
   ],
   "claims_parameter_supported":true,
   "request_parameter_supported":true,
   "request_uri_parameter_supported":true,
   "require_request_uri_registration":false
}
```

#### Get JSON Web Key

##### URL

`/api/oidc/jwks`

##### Method

`GET`

##### Result

##### Success response

Code 200

Content

`jwks` content in JSON format.

Example:

```javascript
{
   "keys":[
      {
         "use":"sig",
         "alg":"RS256",
         "x5c":[
            "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtpMAM4l1H995oqlqdMh\nuqNuffp4+4aUCwuFE9B5s9MJr63gyf8jW0oDr7Mb1Xb8y9iGkWfhouZqNJbMFry+\niBs+z2TtJF06vbHQZzajDsdux3XVfXv9v6dDIImyU24MsGNkpNt0GISaaiqv51NM\nZQX0miOXXWdkQvWTZFXhmsFCmJLE67oQFSar4hzfAaCulaMD+b3Mcsjlh0yvSq7g\n6swiIasEU3qNLKaJAZEzfywroVYr3BwM1IiVbQeKgIkyPS/85M4Y6Ss/T+OWi1Oe\nK49NdYBvFP+hNVEoeZzJz5K/nd6C35IX0t2bN5CVXchUFmaUMYk2iPdhXdsC720t\nBwIDAQAB\n-----END PUBLIC KEY-----"
         ],
         "kid":"h7uJEqXw_h4UXW_wCm3oBuboSGyuxf7XucGDKohPwxo",
         "kty":"RSA",
         "e":"AQAB",
         "n":"AMLaTADOJdR_feaKpanTIbqjbn36ePuGlAsLhRPQebPTCa-t4Mn_I1tKA6-zG9V2_MvYhpFn4aLmajSWzBa8vogbPs9k7SRdOr2x0Gc2ow7Hbsd11X17_b-nQyCJslNuDLBjZKTbdBiEmmoqr-dTTGUF9Jojl11nZEL1k2RV4ZrBQpiSxOu6EBUmq-Ic3wGgrpWjA_m9zHLI5YdMr0qu4OrMIiGrBFN6jSymiQGRM38sK6FWK9wcDNSIlW0HioCJMj0v_OTOGOkrP0_jlotTniuPTXWAbxT_oTVRKHmcyc-Sv53egt-SF9LdmzeQlV3IVBZmlDGJNoj3YV3bAu9tLQc"
      }
   ]
}```

##### Error Response

Code 403

JWK unavailable (if denied by parameter or if the algorithm isn't based on public/private key.

### Manage refresh tokens endpoints

The following endpoints require a valid session cookie to identify the user. If the user has the scope `g_admin`, it's possible to impersonate a user with the optional query parameter `?username={username}`.

#### List refresh tokens

##### URL

`/api/oidc/token`

##### Method

`GET`

##### URL Parameters

Optional

```
`offset`: number, the offset to start the list, default 0
`limit`: number, the number of elements to return, default 100
`pattern`: text, a pattern to filter results, pattern will filter the properties `user_agent` or `issued_for`
`sort`: text, the column to order the results, values available are `authorization_type`, `client_id`, `issued_at`, `last_seen`, `expires_at`, `issued_for`, `user_agent`, `enabled` and `rolling_expiration`
`desc`: no value, is set, the column specified in the `sort` parameter will be orderd by descending order, otherwise ascending
```

##### Result

##### Success response

Code 200

Content

```javascript
[{
  "token_hash": text, refresh token hash signature
  "authorization_type": text, authorization type used to generate this refresh token, value can be "code" or "password"
  "client_id": text, client_id this refresh token was sent to
  "issued_at": number, date when this refresh token was issued, epoch time format
  "expires_at": number, date when this refresh token will expire, epoch time format
  "last_seen": number, last date when this refresh token was used to generate an access token, epoch time format
  "rolling_expiration": boolean, wether this refresh token is a rolling token, i.e. its expiration date will be postponed on each use to generate a new access token
  "issued_for": text, IP address of the device which requested this refresh token
  "user_agent": text, user-agent of the device which requested this refresh token
  "enabled": boolean, set to true if this refresh token is enabled, i.e. can be used to generate new access tokens, or not
}]
```

##### Error Response

Code 403

Access denied

#### Disable a refresh token by its signature

##### URL

`/api/oidc/token/{token_hash}`

##### Method

`DELETE`

##### URL Parameters

Required

```
`token_hash`: text, hash value of the refresh token to disable, must be url-encoded
```

##### Result

##### Success response

Code 200

##### Error Response

Code 403

Access denied

Code 404

Refresh token hash not found for this user

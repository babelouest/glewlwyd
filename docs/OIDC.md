# Glewlwyd OpenID Connect Plugin documentation

This plugin is based on the [OpenID Connect Core 1.0 specification](https://openid.net/specs/openid-connect-core-1_0.html) and allows Glewlwyd to act as an OpenID Provider (OP).

## Functionalities summary

The following OpenID Connect functionalities are currently supported:

- [Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
- [Implicit flow](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth)
- [Hybrid flow](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth)
- [UserInfo Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
- [OAuth 2.0 Multiple Response Types](http://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
- [OpenID Connect Discovery](http://openid.net/specs/openid-connect-discovery-1_0.html)
- [Address Claims](https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim)
- [Requesting Claims using the "claims" Request Parameter](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)
- [Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
- [Client authentication](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) using HTTP Basic Auth, POST Parameter or JWT
- [Passing Request Parameters as JWTs](https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests)
- [Subject Types public or pairwise](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes)
- [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)
- [Token introspection (RFC 7662)](https://tools.ietf.org/html/rfc7662)
- [Token revocation (RFC 7009)](https://tools.ietf.org/html/rfc7009)
- [OpenID Connect Dynamic Registration](http://openid.net/specs/openid-connect-registration-1_0.html)
- [OAuth 2.0 Form Post Response Mode](http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- [Messages encryption](https://openid.net/specs/openid-connect-core-1_0.html#Encryption)

The following OpenID Connect functionalities are not supported yet:

- [Self-Issued OpenID Provider](https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued)

## Messages encryption

Glewlwyd OIDC plugin relies on Rhonabwy library to sign and encrypt tokens. All the JWT signing algorithms are supported but not all the JWT key management encryption algorithms and data encryption algorithms. The discovery endpoint is up-to-date with the supported encryption algorithms.

Concerning key management encryption using symmetric keys, the encryption key is based on a hash of the client secret or the server secret depending on the token to encrypt.

To generate a symmetric key encryption, you must build a SHA256 hash of the secret for the key management encryption algorithms `A128KW`, `A192KW`, `A256KW`, `A128GCMKW`, `A192GCMKW` and `A256GCMKW`. Depending on the alg value, you must use the n first bytes of the hash as follows:
- `A128KW`, `A128GCMKW`: 16 first bytes of the hash
- `A192KW`, `A192GCMKW`: 24 first bytes of the hash
- `A256KW`, `A256GCMKW`: 32 bytes of the hash

If the key management encryption algorithm is `dir`, you must build a SHA256 hash of the secret, then depending on the `enc` value, you must use the n first bytes of the hash as follows:
- `A128CBC-HS256`, `A128GCM`, `A192GCM`, `A256GCM`: 32 first bytes of the hash
- `A192CBC-HS384`: 48 first bytes of the hash
- `A256CBC-HS512`: 64 bytes of the hash

### Access tokens, refresh tokens and code encryption

If the client receives an encrypted access tokens, refresh tokens or code, it must decrypt it in order to use it with Glewlwyd. In particular, the encrypted access token must be decrypted and the nested JWS must be extracted to be usable by Glewlwyd for getting access to userinfo, token revocation or introspection, etc.

## Access token format

As a heir of [Glewlwyd OAuth2 plugin](OAUTH2.md), Glewlwyd OpenID Connect plugin uses JWTs as access tokens. Therefore, the access token can be used by the client or the third party web service to identify the user and the scopes available with this access token.

An access token payload has the following JSON format:

```Javascript
{
  "sub": "4321zyxdcba",      // subject that was provided this access_token
  "aud": "client1",          // client_id the access_token was provided to
  "salt": "abcdxyz1234",     // Random string to avoid collisions
  "type": "access_token",    // Hardcoded
  "iat": 1466556840,         // Issued at time in Epoch Unix format
  "exp": 1466558840,         // Expiration of the token in Epoch Unix format
  "scope":"scope1 g_profile" // scopes granted to this access token in a string separated by spaces
}
```

## Generate a key pair for JWT access tokens signatures

To create a key/certificate pair in RSA or ECDSA format, run the following commands on a linux shell with openssl installed:

```shell
$ # RSA KEY
$ # private key
$ openssl genrsa -out private-rsa.key 4096
$ # public key
$ openssl rsa -in private-rsa.key -outform PEM -pubout -out public-rsa.pem

$ # ECDSA KEY
$ # private key
$ openssl ecparam -genkey -name secp521r1 -noout -out private-ecdsa.key
$ # public key
$ openssl ec -in private-ecdsa.key -pubout -out public-ecdsa.pem
```

For more information on keys generation, see [OpenSSL Documentation](https://www.openssl.org/docs/).

## Installation

![plugin-oidc](screenshots/plugin-oidc.png)

In the administration page, go to `Parameters/Plugins` and add a new plugin by clicking on the `+` button. In the modal, enter a name and a display name (the name must be unique among all user backend instances).
Select the type `Glewlwyd OpenID Connect plugin` in the Type dropdown button.

Below is the definition of all parameters.

### Name

Name (identifier) of the plugin instance, must be unique among all the plugin instances, even of a different type.

### Display name

Name of the instance displayed to the user.

### Issuer

Issuer that will be added in all ID Tokens, must correspond to your Glewlwyd instance URL.

### Subject type identifier

Specify the way to identify subjects.

If the selected value is `public`, the `sub` value in access tokens and id tokens will always have the same value.

If the selected value is `pairwise`, the `sub` value in access tokens and id tokens will have a different values for clients of differents `sector_identifier_uri` or if the `sector_identifier_uri` is empty, for different clients.

### Supported scopes

Specify the list of scopes available in the property `scopes_supported` in the discovery endpoint.

Important note: This list has no effect on what scopes are actually allowed by users for clients in the plugin instance, because by design, all scopes are available fo use. The availability of a scope for a user to a client depends on the configuration of those 3 items, and you can't restrict the use of some socpes in the OpenID Connect plugin.

The meaning of existence of this list is to allow the administrator to choose which scopes will be shown on the discovery endpoint.

Therefore, the administrator can chose to show in the discovery endpoint all scopes, only `openid` (which is mandatory in the specification) or a subset of all scopes available, including `openid`.

### JWT Type

Algorithm used to sign access tokens and ID Tokens.

The algorithm supported are `RSA` and `ECDSA` using a private and a public key, and `SHA` using a shared secret.

### Key size

Size of the key to sign the tokens. The sizes supported are 256 bits, 384 bits or 512 bits.

### Secret key

Private key file used to sign if the selected algorithm is `RSA` or `ECDSA`. Must be a PEM format file.
Shared secret if the selected algorithm is `SHA`.

### Public key

Public key file used to validate access tokens if the selected algorithm is `RSA` or `ECDSA`. Must be a PEM format file.

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

### Additional claims in the ID Token or the /userinfo endpoint

This section allows to add specific claims in ID Tokens or userinfo results and to specify name and e-mail claim handling.

`Name claim` and `E-mail claim` properties can have one of the following values:
- No: The value will never be available on ID Tokens or userinfo results
- On demand: The value will be available if specificly asked in the `claims` parameter
- Mandatory: The value will always be available on ID Tokens or userinfo results

In addition, you can add these claims as scope claims.

If you add additional claims, the options available are the following.

If you specify a type `number`, the value will be converted from a string to an integer.

If the conversion fails, the value will be ignored. If you specify a type `boolean`, you must specify the values for `true` and `false`. If the value doesn't match, it will be ignored.

If you check the option `Mandatory`, the claim will be added in all ID Tokens or userinfo calls, even if the claim isn't requested by the user.

Finally, you add scopes to additional claims.

### Address claim properties

This section allows to specify how to handle address claim.

If the dropdown button `Use claim address` is set to `No`, the claim address isn't available for any user.

If the dropdown button `Use claim address` is set to `On demand` or 'Mandatory', you must specify which properties available in the user profile will match the address claim properties.

If an address claim property is empty or its corresponding property value in the user profile is empty or unavailable, the value will not be present in the address claim. If the address claim is empty, it will not be present in the result.

## Claims request

You can specify claims in your request according to the ["claims" request parameter](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims). The claims request parameter can be present in the url in JSON format url-encoded if the HTTP method is `GET`, in the post body parameter in JSON format url-encoded if the HTTP method is `POST`, or in the JWT payload if you use JWT request parameter.

The supported options for a claim are `null`, `value` and `values`. Option `essential` isn't supported.

For example:

```Javascript
{
 "userinfo":
  {
   "given_name": null,
   "nickname": null,
   "email": {"value": "dev@glewlwyd.tld"},
   "picture": null,
  },
 "id_token":
  {
   "acr": {"values": ["urn:mace:incommon:iap:silver"] }
  }
}
```

To have a claim available in the claim request, it must be set to `on-demand` in the plugin configuration.

## JWT requests, public keys and JWKS

### Allow passing request parameter as JWT

Allow using request parameters as JWT with `request` objects or `request_uri` links.

### Allow request_uri and jwks_uri to a unsecure https:// uri

If the specified `request_uri` link points to an unsecure https:// page with invalid certificate or hostname, allow it anyway.

Warning! This may lead to unsecure connections or MITM attacks.

### Maximum expiration time authorized for JWT requests

Maximum time a token JWT request is allowed to use in seconds. A JWT request with a higher expiration time will be refused.

### pubkey property

Enter the client property that will hold a public key in PEM format.

### JWKS property

Enter the client property that will hold the JWKS of the client.

### JWKS_URI property

Enter the client property that will hold the JWKS_URI of the client. The JWKS will be downloaded each time the JWKS is requested.

## Encrypt out tokens

### Allow out token encryption

Allow to encrypt out tokens for client that have an encryption setup.

### enc property

Enter the client property that will hold the `enc` of the client. If not set, the `enc` value will be set to default `A128CBC-HS256`.

### alg property

Enter the client property that will hold the `alg` of the client. If not set token encryption will be disabled for all.

### kid_alg property

Enter the client property that will hold the `kid_alg` of the client. Mandatory if the client uses jwks, ignored if the client uses a public key in PEM format.

### encrypt_code property

Enter the client property that will hold the `encrypt_code` flag of the client. This property value will tell if the client allows to encrypt authorization code.

### encrypt_at property

Enter the client property that will hold the `encrypt_at` flag of the client. This property value will tell if the client allows to encrypt access tokens.

### encrypt_userinfo property

Enter the client property that will hold the `encrypt_userinfo` flag of the client. This property value will tell if the client allows to encrypt userinfo when sent as JWT.

### encrypt_id_token property

Enter the client property that will hold the `encrypt_id_token` flag of the client. This property value will tell if the client allows to encrypt id_tokens.

### encrypt_refresh_token property

Enter the client property that will hold the `encrypt_refresh_token` flag of the client. This property value will tell if the client allows to encrypt refresh tokens code.

## PKCE - Code challenge (RFC 7636)

This section is used to configure [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636).

### PKCE allowed

Enable this feature if you want to support code challenge.

### Method plain allowed

Enable this feature if you want to allow method `plain` in the code challenge feature. It is not recommended to enable this feature unless you know what you do because this feature is slightly less secure than default method `S256`.

According to [the specifications](https://tools.ietf.org/html/rfc7636#section-4.2):

```
Clients are
permitted to use "plain" only if they cannot support "S256" for some
technical reason and know via out-of-band configuration that the
server supports "plain".
```

## Tokens Introspection (RFC 7662) and Revocation (RFC 7009)

**IMPORTANT NOTICE!**

Glewlwyd access tokens are [JWTs](https://tools.ietf.org/html/rfc7519), the original way for resource services to check if an access token or an id_token is valid and reliable is to check its signature and its expiration date. Token introspection and revocation have been introduced in Glewlwyd, but if the resource service doesn't use the introspection endpoint, it will miss an inactive token and still consider it valid.

The endpoints `/userinfo`, `/introspect` and `/revoke` when they are given an access token to authenticate will check if the token is revoked or not.

### Allow tokens introspection and invocation

Enable this feature if you want your oauth2 instance to enable endpoints `/introspect` and `/revoke`.

### Allow for the token client

Enable this feature if your want to allow clients to use endpoints `/introspect` and `/revoke` using their client_id and secret as HTTP Basic Auth. The clients will be allowed to introspect and revoke only the tokens that were issued for them.

### Required scopes in the access token

Add on or more scopes if you want to allow to use endpoints `/introspect` and `/revoke` using valid access tokens to authenticate the requests. The access tokens must have the scopes required in their payload to be valid.

## Clients registration

This section is used to parameter client registration as defined in [OpenID Connect Dynamic Registration](http://openid.net/specs/openid-connect-registration-1_0.html). If enabled, the administrator can (should?) require an access token with the proper scope to be able to register a new client.

How this `acces_token` is provided is out of scope of this documentation.

### Allow client regisration via API /register

Enable this feature if you want to enable client registration endpoint `/register`.

### Required scopes in the access token

Add on or more scopes if you want to allow to use endpoint `/register` using valid access tokens to authenticate the requests. The access tokens must have the scopes required in their payload to be valid.

### Scopes to add to the new clients

Default scopes that will be added to the registered clients, can be empty. This scope list is only used in `client_credentials` response type.

## Client secret vs password

When you add or edit a client in Glewlwyd, you can set a `client secret` or a `password`. Both can be used to authenticate confidential clients.

The primary difference is that a client secret is a string stored 'as is' in the backend (database or LDAP), without hashing, where a client password is stored in a hashed form in the backend, so makes it more difficult for attackers to retrieve it.

A client secret has priority over a client password, which means that if a client has set both client secret and client password, the authentication will be executed with client secret only.

The `client secret` can also be used to authenticate a client using the method `client_secret_jwt`.

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
- [Token introspection and revocation](#token-introspection-and-revocation)
  - [Token introspection](#token-introspection)
  - [Token revocation](#token-revocation)
- [Client registration](#client-registration)

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

`GET`, `POST`

#### Security

A valid access token is required to access tis endpoint. The user shown in this endpoint result will be the one the access token was created for.

#### URL or POST body Parameters

Optional

```
claims: text, list of additional claims separated by space
format=jwt: send the result in JSON Web Token (JWT) format
```

#### Header parameters

Optional

```
Accept: application/jwt - send the result in JSON Web Token (JWT) format
```

##### Result

##### Success response

Code 200

**JSON Format**

Content

```javascript
{
  "sub": text, subject of the endpoint (user)
  "name": text, name of the user
  "email": text, email of the user
}
```

**JWT Format**

Content

```javascript
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
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
}
```

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

### Token introspection and revocation

The endpoints `POST` `/introspect` and `POST` `/revoke` are implentations of the corresponding RFCs [Token introspection and revocation](https://tools.ietf.org/html/rfc7662) and [OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009).

Both of them rely on 2 distinct ways to authenticate:
- HTTP Basic Auth corresponding to the client credentials whose client the token was submitted
- Authorized Access Token that includes the required scopes for those endpoints

Both authentication methods are non eclusive and the administrator may enable or disable each of them.

#### Token introspection

##### URL

`/api/glwd/introspect`

##### Method

`POST`

##### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
token: text, the token to introspect, required
token_type_hint: text, optional, values available are 'access_token', 'refresh_token' or 'id_token'
```

##### Result

##### Success response

Code 200

Content

Active token
```javascript
{
  "sub": text, identifier for the user associated to the token, if any
  "aud": text, identifier for the client associated to the token, if any
  "username": text, username the token was issued for, if any
  "client_id": text, client the token was issued for, if any
  "iat": number, epoch time when the token was issued
  "nbf": number, epoch time when the token was issued
  "exp": number, epoch time when the token will be (or is supposed to be) expired
  "scope": text, scope list this token was emitted with, separated with spaces
  "token_type": text, type of the token, values may be 'access_token', 'refresh_token' or 'id_token'
}
```

##### Error Response

Code 401

Access denied

Code 400

Invalid parameters

#### Token revocation

##### URL

`/api/glwd/revoke`

##### Method

`POST`

##### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
token: text, the token to introspect, required
token_type_hint: text, optional, values available are 'access_token', 'refresh_token' or 'id_token'
```

##### Result

##### Success response

Code 200

##### Error Response

Code 401

Access denied

Code 400

Invalid parameters

### Client registration

##### URL

`/api/glwd/introspect`

##### Method

`POST`

##### Data Parameters

Input data must be a JSON object.

```javascript
{
  "client_name": text, name of the new client
  "redirect_uris": array of strings, each string must be a 'https://' or http://localhot' url, at least one value is mandatory
  "response_types": array of strings, values available are 'code', 'token', 'id_token', 'password', 'client_credentials', 'refresh_token' or 'delete_token', if empty the client will have the response types 'code' and 'refresh_token'
  "application_type": text, values available are 'web' or 'native'
  "contacts": array of strings
  "client_confidential": boolean, if false then no client_secret will be provided
  "logo_uri": string, url using the format 'https://' or 'http://'
  "client_uri": string, url using the format 'https://' or 'http://'
  "policy_uri": string, url using the format 'https://' or 'http://'
  "tos_uri": string, url using the format 'https://' or 'http://'
  "jwks_uri": string, url using the format 'https://'
  "jwks": JWKS object
}
```

Parameters `jwks_uri` and `jwks` can't coexist at the same time.

##### Result

##### Success response

Code 200

Content

This is a non normative sample response.

```javascript
{
  "client_name": "New Client",
  "client_id": "i4bmq8izuc8c65p8", 
  "client_secret": "EpurvxmR712c1WPfMUtiXWxsA6ReFw9B", 
  "client_id_issued_at": 1583695374, 
  "client_secret_expires_at": 0,
  "redirect_uris": ["https://client.tld/callback"], 
  "response_types": ["code", "token", "id_token", "password", "client_credentials", "refresh_token", "delete_token"], 
  "application_type": "web", 
  "contacts": ["contact@client.tld"], 
  "logo_uri": "https://client.tld/logo.png", 
  "client_uri": "https://client.tld/", 
  "policy_uri": "https://client.tld/policy", 
  "tos_uri": "https://client.tld/tos", 
  "jwks": {"keys": [{"kty": "EC", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", "use": "enc", "kid": "1"}]}
}
```

##### Error Response

Code 401

Access denied

Code 400

Invalid parameters

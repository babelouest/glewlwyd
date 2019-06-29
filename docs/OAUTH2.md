# Glewlwyd OAuth 2 endpoints specifications

This document is intended to describe Glewlwyd OAuth 2 plugin implementation.

OAuth endpoints are used to authenticate the user, and to send tokens or other authentication and identification data. The complete specification is available in the [OAuth 2 RFC document](https://tools.ietf.org/html/rfc6749). If you see an issue or have a question on Glewlwyd OAuth 2 plugin implementation, you can open an issue or send an email to the following address [mail@babelouest.org](mail@babelouest.org).

- [Endpoints authentication](#endpoints-authentication)
- [Prefix](#prefix)
- [Login and grant URIs](#login-and-grant-uris)
- [Scope](#scope)
- [OAuth 2 endpoints](#oauth-2-endpoints)
  - [Authorization endpoint](#authorization-endpoint)
  - [Token endpoint](#token-endpoint)
- [OAuth 2 schemes](#oauth-2-schemes)
  - [Authorization code grant - Authorization request](#authorization-code-grant---authorization-request)
  - [Authorization code grant - Authorization Response](#authorization-code-grant---authorization-response)
  - [Implicit Grant](#implicit-grant)
  - [Resource Owner Password Credentials Grant](#resource-owner-password-credentials-grant)
  - [Client Credentials Grant](#client-credentials-grant)
  - [Refresh token](#refresh-token)
  - [Invalidate refresh token](#invalidate-refresh-token)
- [Manage refresh tokens endpoints](#manage-refresh-tokens-endpoints)
  - [List refresh tokens](#list-refresh-tokens)
  - [Disable a refresh token by its signature](#disable-a-refresh-token-by-its-signature)

## Endpoints authentication

Authentication has different faces, and differs with the authorization scheme.

## Prefix

All URIs are based on the prefix you will setup. In this document, all API endpoints will assume they use the prefix `/api/glwd`, and all static file endpoints will assume they use the prefix `/app`.

## Login and grant URIs

In this document, the login URI will be displayed as `http://login.html`, this will be replaced by the values from your environment that you can define in the config file.

## OAuth 2 endpoints

### Authorization endpoint

This is a multi-method, multi-parameters, versatile endpoint, used to provide authentication management. It handles the following authorization schemes as describe in the [OAuth 2 RFC document](https://tools.ietf.org/html/rfc6749):

- Authorization Code Grant (Authorization part)
- Implicit Grant

#### URL

`/api/glwd/auth`

#### Method

`GET`
`POST`

### Token endpoint

This endpoint is used to provide tokens to the user. It handles the following authorization schemes as describe in the [OAuth 2 RFC document](https://tools.ietf.org/html/rfc6749):

- Authorization Code Grant (Access Token part)
- Resource Owner Password Credentials Grant
- Client Credentials Grant
- Refreshing a token
- Deleting a token

#### URL

`/api/glwd/token`

#### Method

`POST`

## OAuth 2 schemes

Each scheme is described in the following chapter. The description may not be as complete as the [OAuth 2 RFC document](https://tools.ietf.org/html/rfc6749), consider the RFC as the authority standard.

### Authorization code grant - Authorization request

#### URL

`/api/glwd/auth`

#### Method

`GET`
`POST`

#### URL (GET) or body (POST) Parameters

Required

```
`response_type`: text, must be set to `code`
`client_id`: text, client_id that sends the request on behalf of the resource owner, must be a valid client_id
`redirect_uri`: text, redirect_uri to send the resource owner to after the connection, must be a valid redirect_uri for the specified client_id
`scope`: text, scope list that the resource owner will grant access to the client, multiple scope values must be separated by a space
```

Optional

`state`: text, an identifier used to prevent requests collisions and bypass, will be sent back as is to the client

#### Result

##### Resource owner not authenticated

Code 302

Resource owner is not authenticated with a valid session token.

Redirect to `http://login.html?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&additional_parameters` for authentication.

See login paragraph for details.

##### Scope not granted to the client

Code 302

Redirect to `http://login.html?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&additional_parameters` for grant access.

##### Success response

Code 302

Redirect to `redirect_uri`?code=`code`&state=`state`

with `redirect_uri` specified in the request, a `code` generated for the access, and the state specified in the request if any.

##### Error Scope

Scope is not allowed for this user

Code 302

Redirect to `redirect_uri`?error=invalid_scope&state=`state`

with `redirect_uri` specified in the request, `invalid_scope` as error value, and the state specified in the request if any.

##### Error client

Client is invalid, redirect_uri is invalid for this client, or client is not allowed to use this scheme

Code 302

Redirect to `redirect_uri`?error=unauthorized_client&state=`state`

with `redirect_uri` specified in the request, `unauthorized_client` as error value, and the state specified in the request if any.

### Authorization code grant - Authorization Response

#### URL

`/api/glwd/token`

#### Method

`POST`

#### Security

If `client_id` refers to a confidential client, then client_id and client_password must be sent via Basic HTTP Auth.

#### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "authorization_code".
code: text, required
redirect_uri: text, must be same redirect_uri used in the authorization request that sent back this code
client_id: text, must be the same client_id used in the authorization request that sent back this code
```

#### Success response

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

#### Error Response

Code 400

Error input parameters

The combination code/redirect_uri/client_id is incorrect.

### Implicit Grant

#### URL

`/api/glwd/auth`

#### Method

`GET`

#### URL Parameters

Required

```
`response_type`: text, must be set to `token`
`client_id`: text, client_id that sends the request on behalf of the resource owner, must be a valid client_id
`redirect_uri`: text, redirect_uri to send the resource owner to after the connection, must be a valid redirect_uri for the specified client_id
`scope`: text, scope list that the resource owner will grant access to the client, multiple scope values must be separated by a space
```

Optional

`state`: text, an identifier used to prevent requests collisions and bypass, will be sent back as is to the client

#### Result

##### Resource owner not authenticated

Code 302

Resource owner is not authenticated with a valid session token.

Redirect to `http://login.html?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&additional_parameters` for authentication.

See login paragraph for details.

##### Scope not granted to the client

Code 302

Redirect to `http://grant.html?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&additional_parameters` for grant access.

See grant paragraph for details.

##### Success response

Code 302

Redirect to `redirect_uri`#token=`token`&state=`state`

with `redirect_uri` specified in the request, a `code` generated for the access, and the state specified in the request if any.

##### Error Scope

Scope is not allowed for this user

Code 302

Redirect to `redirect_uri`#error=invalid_scope&state=`state`

with `redirect_uri` specified in the request, `invalid_scope` as error value, and the state specified in the request if any.

##### Error client

Client is invalid, redirect_uri is invalid for this client, or client is not allowed to use this scheme

Code 302

Redirect to `redirect_uri`#error=unauthorized_client&state=`state`

with `redirect_uri` specified in the request, `unauthorized_client` as error value, and the state specified in the request if any.

### Resource Owner Password Credentials Grant

#### URL

`/api/glwd/token`

#### Method

`POST`

#### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "password".
username: text
password: text
scope: text
```

#### Success response

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

#### Error Response

Code 403

username or password invalid.

### Client Credentials Grant

#### URL

`/api/glwd/token`

#### Method

`POST`

#### Security

HTTP Basic authentication with client_id/client_password credentials. Client_id must be set as confidential

#### URL Parameters

Required

Optional

#### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "client_credentials".
scope: text
```

#### Success response

Code 200

Content

```javascript
{
  "access_token":text, jwt token
  "token_type":text, value is "bearer",
  "expires_in":number, set by server configuration
}
```

#### Error Response

Code 403

Access denied

### Refresh token

Send a new access_token based on a valid refresh_token

#### URL

`/api/glwd/token`

#### Method

`POST`

#### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "refresh_token".
refresh_token: text, a valid ref refresh_token, mandatory
scope: text, must the same scope or a sub scope of the scope used to provide the refresh_token, optional
```

#### Success response

Code 200

Content

```javascript
{
  "access_token":text, jwt token
  "token_type":text, value is "bearer",
  "expires_in":number, set by server configuration
}
```

#### Error Response

Code 400

Error input parameters

### Invalidate refresh token

Mark a refresh_token as invalid, to prevent further access_token to be generated

#### URL

`/api/glwd/token`

#### Method

`POST`

#### Data Parameters

Request body parameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "delete_token".
refresh_token: text, a valid refresh_token, mandatory
```

#### Success response

Code 200

#### Error Response

Code 400

Error input parameters

## Manage refresh tokens endpoints

The following endpoints require a valid session cookie to identify the user. If the user has the scope `g_admin`, it's possible to impersonate a user with the optional query parameter `?username={username}`.

### List refresh tokens

#### URL

`/api/glwd/profile/token`

#### Method

`GET`

#### URL Parameters

Optional

```
`offset`: number, the offset to start the list, default 0
`limit`: number, the number of elements to return, default 100
`pattern`: text, a pattern to filter results, pattern will filter the properties `user_agent` or `issued_for`
`sort`: text, the column to order the results, values available are `authorization_type`, `client_id`, `issued_at`, `last_seen`, `expires_at`, `issued_for`, `user_agent`, `enabled` and `rolling_expiration`
`desc`: no value, is set, the column specified in the `sort` parameter will be orderd by descending order, otherwise ascending
```

#### Result

#### Success response

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

#### Error Response

Code 403

Access denied

### Disable a refresh token by its signature

#### URL

`/api/glwd/profile/token/{token_hash}`

#### Method

`DELETE`

#### URL Parameters

Required

```
`token_hash`: text, hash value of the refresh token to disable, must be url-encoded
```

#### Result

#### Success response

Code 200

#### Error Response

Code 403

Access denied

Code 404

Refresh token hash not found for this user

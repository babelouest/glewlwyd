# Glewlwyd OAuth 2 endpoints spceifications

This document is intended to describe Glewlwyd oauth 2 implementation.

OAuth endpoints are used to authenticate the user, and to send tokens or other authentication and identification data. The complete specification is available in the [OAuth 2 RFC document](https://tools.ietf.org/html/rfc6749). If you see an issue or have a question on Glewlwyd OAuth 2 implementation, you can open an issue or send an email at the following address [mail@babelouest.org](mail@babelouest.org).

## Endpoints authentication

Authentication has different faces, and differs with the authorization scheme.

## Prefix

All URIs are based on the prefix you will setup. In this document, all API endpoints will assume they use the prefix `/glewlwyd`, and all static file endpoints will assume they use the prefix `/app`.

## Login and grant URIs

In this document, the login URI will be displayed as `http://login.html` and the grant URI will be displayed as `http://grant.html`, this will be replaced by the values from your environment that you can define in the config file.

## Scope

In this document, we assume that scope is enabled in glewlwyd server configuration. If scope is disabled, then all scope values will be ignored in all requests and no scope will be sent in the responses.

## OAuth 2 endpoints

### Authorization endpoint

This is a multi-method, multi-parameters, versatile endpoint, used to provide authentication management. It handles the following authorization schemes as describe in the [OAuth 2 RFC document](https://tools.ietf.org/html/rfc6749):

- Authorization Code Grant (Authorization part)
- Implicit Grant

#### URL

`/glewlwyd/auth`

#### Method

`GET`

### Token endpoint

This endpoint is used to provide tokens to the user. It handles the following authorization schemes as describe in the [OAuth 2 RFC document](https://tools.ietf.org/html/rfc6749):

- Authorization Code Grant (Access Token part)
- Resource Owner Password Credentials Grant
- Client Credentials Grant
- Refreshing a token
- Deleting a token

#### URL

`/glewlwyd/token`

#### Method

`POST`

## OAuth 2 schemes

Each scheme is described in the following chapter. The description may not be as complete as the [OAuth 2 RFC document](https://tools.ietf.org/html/rfc6749), consider the RFC as the authority standard.

### Authorization code grant - Authorization request

#### URL

`/glewlwyd/auth`

#### Method

`GET`

#### URL Parameters

Required

```
`response_type`: text, must be set to `code`
`client_id`: text, client_id that sends the request on behalf of the resource owner, must be a valid client_id
`redirect_uri`: text, redirect_uri to send the resource owner to after the connection, must ba a valid redirect_uri for the specified client_id
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

Redirect to `redirect_uri`#code=`code`&state=`state`

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

### Authorization code grant - Authorization Response

#### URL

`/glewlwyd/token`

#### Method

`POST`

#### Security

If `client_id` refers to a confidential client, then client_id and client_password must be sent via Basic HTTP Auth.

#### Data Parameters

Request body arameters must be encoded using the `application/x-www-form-urlencoded` format.

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

`/glewlwyd/auth`

#### Method

`GET`

#### URL Parameters

Required

```
`response_type`: text, must be set to `token`
`client_id`: text, client_id that sends the request on behalf of the resource owner, must be a valid client_id
`redirect_uri`: text, redirect_uri to send the resource owner to after the connection, must ba a valid redirect_uri for the specified client_id
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

`/glewlwyd/token`

#### Method

`POST`

#### Data Parameters

Request body arameters must be encoded using the `application/x-www-form-urlencoded` format.

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

`/glewlwyd/token`

#### Method

`POST`

#### Security

HTTP Basic authentication with client_id/client_password credentials. Client_id must be set as confidential

#### URL Parameters

Required

Optional

#### Data Parameters

Request body arameters must be encoded using the `application/x-www-form-urlencoded` format.

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

Send a new access_token based on a valid reresh_token

#### URL

`/glewlwyd/token`

#### Method

`POST`

#### Data Parameters

Request body arameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "refresh_token".
refresh_token: text, a valid refres_token, mandatory
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

Mark a refresh_token as invalid, to prevent further access_toen to be generated

#### URL

`/glewlwyd/token`

#### Method

`POST`

#### Data Parameters

Request body arameters must be encoded using the `application/x-www-form-urlencoded` format.

```
grant_type: text, must be set to "delete_token".
refresh_token: text, a valid refres_token, mandatory
```

#### Success response

Code 200

#### Error Response

Code 400

Error input parameters

# Glewlwyd API description

This document is intended to describe all data API endpoints. Data API endpoints are Glewlwyd specific endpoints used to manage data such as users, passwords, clients, scope names, resources, and disable refresh tokens.

For OAuth 2 endpoints specification, please read the document OAUTH2.md.

## Endpoints authentication

All the endpoints require proper authentication to provide their service. The authentication method used is [Bearer Token](https://tools.ietf.org/html/rfc6750). For each endpoint, the scope required will be defined in the `Security` paragraph. The admin scope name is `g_admin`, but this value can be changed in the configuration file.

## Prefix

All urls are based on the prefix you will setup. In this document, all endpoints will assume they use the prefix `/glewlwyd`.

## Content-type

All request and response body use `application/json` content-type.

## Error response

The HTTP status codes used are the following:
- 200 OK: no error
- 400 Invlid parameters: The user has sent invalid data. The details of all the errors are sent in the response body
- 404 Not found: The specified resource doesn't exist
- 500 Server error: An error occured on the server

## Authentication API

### Get current user authentication profile data

#### URL

`/glewlwyd/user/auth/`

#### Method

`GET`

#### Security

Session token or header bearer token

#### Success response

Code 200

Content

```javascript
{
  name: text,
  email: text,
  login: text,
  scope: [ // Array of strings
  ]
}
```

### Authenticate a user with its login and password

#### URL

`/glewlwyd/auth/user/`

#### Method

`POST`

#### Security

none

#### Data Parameters

Request body arameters must be encoded using the `application/x-www-form-urlencoded` format.

```
username: text, required
password: text, required
```

#### Success response

Code 200

A session cookie containing a valid token

#### Error Response

Code 400

Error input parameters

Content: json array containing all errors

### Disable current session cookie

#### URL

`/glewlwyd/auth/user/`

#### Method

`DELETE`

#### Security

Session token

#### Success response

Code 200

Stored session cookie will be disabled.

Code 400

Error input parameters

Content: json array containing all errors

## Grant scope API

### Get user scope grant

Return the list of scope available for the connected user

#### URL

`/glewlwyd/auth/grant`

#### Method

`GET`

#### Security

Session token or header bearer token

#### URL Parameters

#### Success response

Code 200

Content

```javascript
[
  {
    name: text,
    description: text
  }
]
```

### Grant access to scope for a client

#### URL

`/glewlwyd/auth/grant`

#### Method

`POST`

#### Security

Session token or header bearer token

#### Data Parameters

Request body arameters must be encoded using the `application/x-www-form-urlencoded` format.

```
client_id: text, required
scope: text, required, list of scope values separated by space
```

#### Success response

Code 200

#### Error Response

Code 400

Error input parameters

Content: json array containing all errors

### Delete grant access to scope for a client

#### URL

`/glewlwyd/auth/grant`

#### Method

`DELETE`

#### Security

Session token or header bearer token

#### Data Parameters

Request body arameters must be encoded using the `application/x-www-form-urlencoded` format.

```
client_id: text, required
scope: text, required, list of scope values separated by space
```

#### Success response

Code 200

#### Error Response

Code 400

Error input parameters

Content: json array containing all errors

## Profile API

### Get current profile

#### URL

`/glewlwyd/profile/`

#### Method

`GET`

#### Security

Session token or header bearer token

#### Success response

Code 200

Content

```javascript
{
  name: text,
  email: text,
  login: text,
  scope: [ // Array of strings
  ]
}
```

### Update current profile

#### URL

`/glewlwyd/profile/`

#### Method

`POST`

#### Security

Session token or header bearer token

#### Data Parameters

```javascript
{
  name: text, maximum 256 characters, optional
  email: text, maximum 256 characters, optional
  old_password: text, optional
  new_password: text, mandatory if old_password is set
}
// At least one optional value must be set
```

#### Success response

Code 200

#### Error Response

Code 400

Error input parameters

Content: json array containing all errors

## authorization type API

### Get all authorization type status

#### URL

`/glewlwyd/authorization/`

#### Method

`GET`

#### Security

Scope required: `g_admin`

#### Success response

Code 200

Content

```javascript
[
  {
    name: text,
    description: text,
    enabled: boolean
  }
]
```

### Get a specific authorization type status

#### URL

`/glewlwyd/authorization/:authorization_type`

#### Method

`GET`

#### Security

Scope required: `g_admin`

#### Success response

Code 200

Content

```javascript
{
  name: text,
  description: text,
  enabled: boolean
}
```

#### Error Response

Code 404

Resource not found

### Update one response type status

#### URL

`/glewlwyd/authorization/:authorization_type`

#### Method

`PUT`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`authorization_type`: authorization type name

#### Data Parameters

```javascript
{
  description: text, maximum 256 characters, optional
  enabled: boolean, optional
}
```

#### Success response

Code 200

#### Error Response

Code 404

Resource not found

Code 400

Error input parameters

Content: json array containing all errors

## Scope API

### Get the list of available scopes

#### URL

`/glewlwyd/scope`

#### Method

`GET`

#### Security

Scope required: `g_admin`

#### Success response

Code 200

Content

```javascript
[
  {
    name: text,
    description: text
  }
]
```

### Get a specific scope

#### URL

`/glewlwyd/scope/:scope_name`

#### Method

`GET`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`scope_name`: name of the scope

#### Success response

Code 200

Content

```javascript
{
  name: text,
  description: text
}
```

#### Error Response

Code 404

Resource not found

### Add a new scope

#### URL

`/glewlwyd/scope`

#### Method

`POST`

#### Security

Scope required: `g_admin`

#### Data Parameters

```javascript
{
  name: text, maximum 128 characters, name must be unique, mandatory
  description: text, maximum 512 characters, optional
}
```

#### Success response

Code 200

#### Error Response

Code 400

Error input parameters

Content: json array containing all errors

### Update a scope

#### URL

`/glewlwyd/scope/:scope_name`

#### Method

`PUT`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`scope_name`: name of the scope

#### Data Parameters

```javascript
{
  description: text, maximum 512 characters, optional
}
```

#### Success response

Code 200

#### Error Response

Code 404

Resource not found

Code 400

Error input parameters

Content: json array containing all errors

### Delete an existing scope

#### URL

`/glewlwyd/scope/:scope_name`

#### Method

`DELETE`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`scope_name`: name of the scope

#### Success response

Code 200

#### Error Response

Code 404

Resource not found

## User API

The user API allows user CRUD. You can have LDAP or Database backend to store users, or both. Once a user is created in a backend, ldap or database, it can be modified, but the login or the backend can't be updated.

### Get the list of users

#### URL

`/glewlwyd/user?source&offset&limit`

#### Method

`GET`

#### Security

Scope required: `g_admin`

#### URL Parameters

Optional

`source`: source to get the user data: vaues can be `database`, `ldap` or `all` default is `all`

`offset`: offset to start the list result, default is 0

`limit`: number of users to list, default is 20

#### Success response

Code 200

Content

```javascript
[ // An array of user objects
  {
    source: text,
    name: text,
    email: text,
    login: text,
    enabled: boolean,
    scope: [ // Array of strings
    ]
  }
]
```

### Get a specific user

#### URL

`/glewlwyd/user/{login}?source`

#### Method

`GET`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`login`: user login

Optional

`source`: source to get the user data: vaues can be `database`, `ldap` or `all` default is `all`

#### Success response

Code 200

Content

```javascript
{
  source: text,
  name: text,
  email: text,
  login: text,
  enabled: boolean,
  scope: [ // Array of strings
  ]
}
```

#### Error Response

Code 404

Resource not found

### Create a new user

#### URL

`/glewlwyd/user`

#### Method

`POST`

#### Security

Scope required: `g_admin`

#### Data Parameters

```javascript
{
  source: text, values can be "database" or "ldap", optional, default is "database"
  name: text, maximum 256 characters, optional
  email: text, maximum 256 characters, optional
  login: text, maximum 128 characters, mandatory
  password: text, minimum 8 characters, mandatory
  enabled: boolean, default true
  scope: [ // Array of strings
  ]
}
```

#### Success response

Code 200

#### Error Response

Code 400

Error input parameters

Content: json array containing all errors

### Update an existing user

If no password is specified in the request, the password is not changed.

#### URL

`/glewlwyd/user/{login}?source`

#### Method

`PUT`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`login`: user login

Optional

`source`: source to get the user data: vaues can be `database`, `ldap` or `all` default is `all`

#### Data Parameters

```javascript
{
  name: text, maximum 256 characters, optional
  email: text, maximum 256 characters, optional
  password: text, minimum 8 characters, optional
  enabled: boolean, default true
  scope: [ // Array of strings
  ]
}
```

#### Success response

Code 200

#### Error Response

Code 404

Resource not found

Code 400

Error input parameters

Content: json array containing all errors

### Delete an existing user

#### URL

`/glewlwyd/user/{login}?source`

#### Method

`DELETE`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`login`: user login

Optional

`source`: source to get the user data: vaues can be `database`, `ldap` or `all` default is `all`

#### Success response

Code 200

#### Error Response

Code 404

Resource not found

## Client API

The client API allows client CRUD. You can have LDAP or Database backend to store clients, or both. If you ose both, then the LDAP backend is checked first, if no client with this credentials exist, then the Database backend is checked. If you use the LDAP backend, make sure that the client specified in `bind_dn` config file parameter has proper credentials to list, create, modify and update entries.

### Get the list of clients

#### URL

`/glewlwyd/client`

#### Method

`GET`

#### Security

Scope required: `g_admin`

#### Success response

Code 200

Content

```javascript
[ // An array of client objects
  {
    name: text,
    description: text,
    client_id: text,
    confidential: boolean,
    enabled: boolean,
    scope: [ // Array of strings
    ],
    redirect_uri: [
      {
        name: text,
        uri: text,
        enabled: true
      }
    ],
    authorization_type: [ // Array of strings
    ]
  }
]
```

### Get a specific client

#### URL

`/glewlwyd/client/{client_id}`

#### Method

`GET`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`client_id`: client_id

#### Success response

Code 200

Content

```javascript
{
  name: text,
  description: text,
  client_id: text,
  confidential: boolean,
  enabled: boolean,
  scope: [ // Array of strings
  ],
  redirect_uri: [
    {
      name: text,
      uri: text,
      enabled: true
    }
  ],
  authorization_type: [ // Array of strings
  ]
}
```

#### Error Response

Code 404

Resource not found

### Create a new client

#### URL

`/glewlwyd/client`

#### Method

`POST`

#### Security

Scope required: `g_admin`

#### Data Parameters

```javascript
{
  name: text, maximum 128 characters, mandatory
  description: text, maximum 256 characters, optional
  client_id: text, maximum 128 characters, must be unique, mandatory
  confidential: boolean, optional, default false
  enabled: boolean, optional, default true
  password: text, minimum 8 characters, mandatory if confidential is true
  scope: [ // Array of strings, at least one value is mandatory if confidential is true
  ],
  redirect_uri: [ // Array of redirect_uri, at least one value is mandatory
    {
      name: text, maximum 128 characters, mandatory, must be unique within the client
      uri: text, maximum 512 characters, mandatory
      enabled: boolean, optional, default true
    }
  ],
  authorization_type: [ // Array of strings, must be valid authorization_type
  ]
}
```

#### Success response

Code 200

#### Error Response

Code 400

Error input parameters

Content: json array containing all errors

### Update an existing client

If no password is specified in the request, the password is not changed.

#### URL

`/glewlwyd/client/{client_id}`

#### Method

`PUT`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`client_id`: client client_id

#### Data Parameters

```javascript
{
  name: text, maximum 128 characters, mandatory
  description: text, maximum 256 characters, optional
  client_id: text, maximum 128 characters, must be unique, mandatory
  confidential: boolean, optional, default false
  enabled: boolean, optional, default true
  password: text, minimum 8 characters, mandatory if confidential is true
  scope: [ // Array of strings, at least one value is mandatory if confidential is true
  ],
  redirect_uri: [ // Array of redirect_uri, at least one value is mandatory
    {
      name: text, maximum 128 characters, mandatory, must be unique within the client
      uri: text, maximum 512 characters, mandatory
      enabled: boolean, optional, default true
    }
  ],
  authorization_type: [ // Array of strings, must be valid authorization_type
  ]
}
```

#### Success response

Code 200

#### Error Response

Code 404

Resource not found

Code 400

Error input parameters

Content: json array containing all errors

### Delete an existing client

#### URL

`/glewlwyd/client/{client_id}`

#### Method

`DELETE`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`client_id`: client client_id

#### Success response

Code 200

#### Error Response

Code 404

Resource not found

## Resource API

These endpoints allows resource management, although since tokens are JWT, there is no need for resource services to contact Glewlwyd, so it's just an FYI.

### List available resources

#### URL

`/glewlwyd/resource`

#### Method

`GET`

#### Security

Scope required: `g_admin`

#### Success response

Code 200

Content

```javascript
[
  {
    name: text,
    description: text,
    uri: text
  }
]
```

### Get a specific resource

#### URL

`/glewlwyd/resource/:resource_name`

#### Method

`GET`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`resource_name`: name of the resource

#### Success response

Code 200

Content

```javascript
{
  name: text,
  description: text,
  uri: text
}
```

#### Error Response

Code 404

Resource not found

### Add a new resource

#### URL

`/glewlwyd/resource`

#### Method

`POST`

#### Security

Scope required: `g_admin`

#### Data Parameters

```javascript
{
  name: text, maximum 128 characters, mandatory
  description: text, maximum 256 characters, optional
  uri: text, maximum 128 characters, mandatory
}
```

#### Success response

Code 200

#### Error Response

Code 400

Error input parameters

Content: json array containing all errors

### Update an existing resource

#### URL

`/glewlwyd/resource/:resource_name`

#### Method

`PUT`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`resource_name`: name of the resource

#### Data Parameters

```javascript
{
  description: text, maximum 256 characters, optional
  uri: text, maximum 128 characters, mandatory
}
```

#### Success response

Code 200

#### Error Response

Code 404

Resource not found

Code 400

Error input parameters

Content: json array containing all errors

### Delete an existing resource

#### URL

`/glewlwyd/resourceError binding to ldap server mode/:resource_name`

#### Method

`DELETE`

#### Security

Scope required: `g_admin`

#### URL Parameters

Required

`resource_name`: name of the resource

#### Success response

Code 200

#### Error Response

Code 404

Resource not found

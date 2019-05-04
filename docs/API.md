# Glewlwyd API description

This document is intended to describe Glewlwyd's core API endpoints. Glewlwyd's core API endpoints are used to manage core functionalities data.

- [Endpoints authentication](#endpoints-authentication)
- [Prefix](#prefix)
- [Content-type](#content-type)
- [Error response](#error-response)
- Plugins and modules management
  - Get list of all plugin instances available
  - Get all user module instances available
  - Get a user module instance
  - Add a new user module instance
  - Update an existing user module instance
  - Delete an existing user module instance
  - Enable or disable an existing user module instance
  - Get all client module instances available
  - Get a client module instance
  - Add a new client module instance
  - Update an existing client module instance
  - Delete an existing client module instance
  - Enable or disable an existing client module instance
  - Get all user auth scheme module instances available
  - Get a user auth scheme module instance
  - Add a new user auth scheme module instance
  - Update an existing user auth scheme module instance
  - Delete an existing user auth scheme module instance
  - Enable or disable an existing user auth scheme module instance
  - Get all plugin module instances available
  - Get a plugin module instance
  - Add a new plugin module instance
  - Update an existing plugin module instance
  - Delete an existing plugin module instance
  - Enable or disable an existing plugin module instance
- Users management
  - Get a list of users available
  - Get a user
  - Add a new user
  - Update an existing user
  - Delete an existing user
- Clients management
  - Get a list of clients available
  - Get a client
  - Add a new client
  - Update an existing client
  - Delete an existing client
- Scopes management
  - Get a list of scopes available
  - Get a scope
  - Add a new scope
  - Update an existing scope
  - Delete an existing scope
- User authentication
  - Authenticate a user with password
  - Authenticate a user with an authentication scheme
  - Trigger a scheme
  - Change current user with another user authenticated in this session
- User profile
  - Get list of connected profiles
  - Update current profile
  - Change user password for current profile
  - Get sessions for current profile
  - Disable a session for current profile
  - Register an auth scheme for current profile
  - Get registration on an auth scheme for current profile

## Endpoints authentication

All the endpoints require proper authentication to provide their service. The authentication method used is a session cookie. For each endpoint, the scope required will be defined in the `Security` paragraph. The admin scope name is `g_admin`, the profile scope name is `g_profile`, but these values can be changed in the configuration file.

## Prefix

All URLs are based on the prefix you will setup. In this document, all endpoints will assume they use the prefix `/api`.

## Content-type

All request and response body use `application/json` content-type.

## Error response

The HTTP status codes used are the following:
- 200 OK: no error
- 400 Invalid parameters: The user has sent invalid data. The details of all the errors may be present in the response body
- 401 Unauthorized: The user isn't authorized
- 403 Forbidden: The user isn't allowed
- 404 Not found: The specified resource doesn't exist
- 500 Server error: An error occurred on the server

## Plugins and modules management

### Get all modules available

Return the list of all modules available for all types of modules

#### URL

`/api/mod/type/`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

#### Success response

Code 200

Content

```javascript
{
  user: [
    name: string,
    display_name: string
    description: string,
    parameters: object, the parameters of the module for initialization
  ],
  client: [
    name: string,
    display_name: string
    description: string,
    parameters: object, the parameters of the module for initialization
  ],
  scheme: [
    name: string,
    display_name: string
    description: string,
    parameters: object, the parameters of the module for initialization
  ],
  plugin: [
    name: string,
    display_name: string
    description: string,
    parameters: object, the parameters of the plugin for initialization
  ]
}
```

Example

```javascript
TODO
```

### Get all user module instances available

Return the list of all instances available for user modules

#### URL

`/api/mod/user/`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

#### Success response

Code 200

Content

```javascript
[{
  module: string, name of the module
  name: string, name of the instance
  display_name: string
  parameters: object, parameters used for the initialization of this instance
  order_rank: number
  readonly: boolean
  enabled: boolean
}]
```

Example

```javascript
TODO
```

### Get a user module instance

Return the details of a user module instance

#### URL

`/api/mod/user/{name}`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Success response

Code 200

Content

```javascript
{
  module: string, name of the module
  name: string, name of the instance
  display_name: string
  parameters: object, parameters used for the initialization of this instance
  order_rank: number
  readonly: boolean
  enabled: boolean
}
```

Example

```javascript
TODO
```

Code 404

Module not found

### Add a new user module instance

Add a new user module instance

#### URL

`/api/mod/user/`

#### Method

`POST`

#### Security

User with scope `g_admin` authorized.

#### Body Parameters

```javascript
{
  module: string, name of the module, must be an existing user module available
  name: string, name of the instance, maximum 128 characters
  display_name: string, long name of the instance, maximum 256 characters
  parameters: object, parameters used for the initialization of this instance
  order_rank: number, priority of this instance to get a user
  readonly: boolean, set to true if the instance is in read only mode
}
```

#### Success response

Code 200

Instance added

Code 400

Error input parameters

Content

A javascript array with the error messages

### Update an existing user module instance

#### URL

`/api/mod/user/{name}`

#### Method

`PUT`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Body Parameters

```javascript
{
  display_name: string, long name of the instance, maximum 256 characters
  parameters: object, parameters used for the initialization of this instance
  order_rank: number, priority of this instance to get a user
  readonly: boolean, set to true if the instance is in read only mode
}
```

#### Success response

Code 200

Instance updated

Code 404

Instance not found

Code 400

Error input parameters

Content

A javascript array with the error messages

### Delete an existing user module instance

#### URL

`/api/mod/user/{name}`

#### Method

`DELETE`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Success response

Code 200

Instance removed

Code 404

Instance not found

### Enable or disable an existing user module instance

#### URL

`/api/mod/user/{name}/{action}`

#### Method

`PUT`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance
`action`: either `enable` or `disable`

#### Success response

Code 200

Action executed

Code 404

Instance not found

### Get all client module instances available

Return the list of all instances available for client modules

#### URL

`/api/mod/client/`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

#### Success response

Code 200

Content

```javascript
[{
  module: string, name of the module
  name: string, name of the instance
  display_name: string
  parameters: object, parameters used for the initialization of this instance
  order_rank: number
  readonly: boolean
  enabled: boolean
}]
```

Example

```javascript
TODO
```

### Get a client module instance

Return the details of a client module instance

#### URL

`/api/mod/client/{name}`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Success response

Code 200

Content

```javascript
{
  module: string, name of the module
  name: string, name of the instance
  display_name: string
  parameters: object, parameters used for the initialization of this instance
  order_rank: number
  readonly: boolean
  enabled: boolean
}
```

Example

```javascript
TODO
```

Code 404

Module not found

### Add a new client module instance

Add a new client module instance

#### URL

`/api/mod/client/`

#### Method

`POST`

#### Security

User with scope `g_admin` authorized.

#### Body Parameters

```javascript
{
  module: string, name of the module, must be an existing client module available
  name: string, name of the instance, maximum 128 characters
  display_name: string, long name of the instance, maximum 256 characters
  parameters: object, parameters used for the initialization of this instance
  order_rank: number, priority of this instance to get a client
  readonly: boolean, set to true if the instance is in read only mode
}
```

#### Success response

Code 200

Instance added

Code 400

Error input parameters

Content

A javascript array with the error messages

### Update an existing client module instance

#### URL

`/api/mod/client/{name}`

#### Method

`PUT`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Body Parameters

```javascript
{
  display_name: string, long name of the instance, maximum 256 characters
  parameters: object, parameters used for the initialization of this instance
  order_rank: number, priority of this instance to get a client
  readonly: boolean, set to true if the instance is in read only mode
}
```

#### Success response

Code 200

Instance updated

Code 404

Instance not found

Code 400

Error input parameters

Content

A javascript array with the error messages

### Delete an existing client module instance

#### URL

`/api/mod/client/{name}`

#### Method

`DELETE`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Success response

Code 200

Instance removed

Code 404

Instance not found

### Enable or disable an existing client module instance

#### URL

`/api/mod/client/{name}/{action}`

#### Method

`PUT`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance
`action`: either `enable` or `disable`

#### Success response

Code 200

Action executed

Code 404

Instance not found

### Get all user auth scheme module instances available

Return the list of all instances available for user auth scheme modules

#### URL

`/api/mod/scheme/`

#### Method

`GET`

#### Security

user with scope `g_admin` authorized.

#### URL Parameters

#### Success response

Code 200

Content

```javascript
[{
  module: string, name of the module
  name: string, name of the instance
  display_name: string
  parameters: object, parameters used for the initialization of this instance
  enabled: boolean
}]
```

Example

```javascript
TODO
```

### Get a user auth scheme module instance

Return the details of a user auth scheme module instance

#### URL

`/api/mod/scheme/{name}`

#### Method

`GET`

#### Security

user with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Success response

Code 200

Content

```javascript
{
  module: string, name of the module
  name: string, name of the instance
  display_name: string
  parameters: object, parameters used for the initialization of this instance
  enabled: boolean
}
```

Example

```javascript
TODO
```

Code 404

Module not found

### Add a new user auth scheme module instance

Add a new user auth scheme module instance

#### URL

`/api/mod/scheme/`

#### Method

`POST`

#### Security

user with scope `g_admin` authorized.

#### Body Parameters

```javascript
{
  module: string, name of the module, must be an existing user auth scheme module available
  name: string, name of the instance, maximum 128 characters
  display_name: string, long name of the instance, maximum 256 characters
  duration: number, duration of the scheme authentication in seconds
  max_use: number, maximum use of the scheme authentication per session
  parameters: object, parameters used for the initialization of this instance
}
```

#### Success response

Code 200

Instance added

Code 400

Error input parameters

Content

A javascript array with the error messages

### Update an existing user auth scheme module instance

#### URL

`/api/mod/scheme/{name}`

#### Method

`PUT`

#### Security

user with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Body Parameters

```javascript
{
  display_name: string, long name of the instance, maximum 256 characters
  duration: number, duration of the scheme authentication in seconds
  max_use: number, maximum use of the scheme authentication per session
  parameters: object, parameters used for the initialization of this instance
}
```

#### Success response

Code 200

Instance updated

Code 404

Instance not found

Code 400

Error input parameters

Content

A javascript array with the error messages

### Delete an existing user auth scheme module instance

#### URL

`/api/mod/scheme/{name}`

#### Method

`DELETE`

#### Security

user with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Success response

Code 200

Instance removed

Code 404

Instance not found

### Enable or disable an existing user auth scheme module instance

#### URL

`/api/mod/scheme/{name}/{action}`

#### Method

`PUT`

#### Security

user with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance
`action`: either `enable` or `disable`

#### Success response

Code 200

Action executed

Code 404

Instance not found

### Get all plugin module instances available

Return the list of all instances available for plugin modules

#### URL

`/api/mod/plugin/`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

#### Success response

Code 200

Content

```javascript
[{
  module: string, name of the module
  name: string, name of the instance
  display_name: string
  parameters: object, parameters used for the initialization of this instance
  order_rank: number
  readonly: boolean
  enabled: boolean
}]
```

Example

```javascript
TODO
```

### Get a plugin module instance

Return the details of a plugin module instance

#### URL

`/api/mod/plugin/{name}`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Success response

Code 200

Content

```javascript
{
  module: string, name of the module
  name: string, name of the instance
  display_name: string
  parameters: object, parameters used for the initialization of this instance
  order_rank: number
  readonly: boolean
  enabled: boolean
}
```

Example

```javascript
TODO
```

Code 404

Module not found

### Add a new plugin module instance

Add a new plugin module instance

#### URL

`/api/mod/plugin/`

#### Method

`POST`

#### Security

User with scope `g_admin` authorized.

#### Body Parameters

```javascript
{
  module: string, name of the module, must be an existing plugin module available
  name: string, name of the instance, maximum 128 characters
  display_name: string, long name of the instance, maximum 256 characters
  parameters: object, parameters used for the initialization of this instance
  order_rank: number, priority of this instance to get a plugin
  readonly: boolean, set to true if the instance is in read only mode
}
```

#### Success response

Code 200

Instance added

Code 400

Error input parameters

Content

A javascript array with the error messages

### Update an existing plugin module instance

#### URL

`/api/mod/plugin/{name}`

#### Method

`PUT`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Body Parameters

```javascript
{
  display_name: string, long name of the instance, maximum 256 characters
  parameters: object, parameters used for the initialization of this instance
  order_rank: number, priority of this instance to get a plugin
  readonly: boolean, set to true if the instance is in read only mode
}
```

#### Success response

Code 200

Instance updated

Code 404

Instance not found

Code 400

Error input parameters

Content

A javascript array with the error messages

### Delete an existing plugin module instance

#### URL

`/api/mod/plugin/{name}`

#### Method

`DELETE`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance

#### Success response

Code 200

Instance removed

Code 404

Instance not found

### Enable or disable an existing plugin module instance

#### URL

`/api/mod/plugin/{name}/{action}`

#### Method

`PUT`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the instance
`action`: either `enable` or `disable`

#### Success response

Code 200

Action executed

Code 404

Instance not found

## Users management

### Get a list of users available

Return a list of users available

#### URL

`/api/user/`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`offset`: number, the offset to start the list, default 0
`limit`: number, the maximal number of elements in the list, default 100
`source`: string, the instance name to limit the result, if not set, all instances will be used
`pattern`: string, the pattern to filter the result

#### Success response

Code 200

Content

```javascript
[{
  username: string, mandatory
  scope:[
    scope_value: string, mandatory, array can be empty
  ],
  enabled: boolean, mandatory
  name: string, optional
  email: string, optional
  other values: string or array of strings, optional, depends on what's returned by the module instance
}]
```

Example

```javascript
[
  {
    username: "user1",
    scope: [
      "g_profile",
      "scope1",
      "scope2"
    ],
    enabled: true,
    name: "Dave Lopper",
    email: "user1@glewlwyd",
    alias: [
      "dev",
      "plop"
    ]
  },
  {
    username: "user2",
    scope: [
      "g_profile"
    ],
    enabled: true,
    name: "Dave Lopper 2",
    email: "user2@glewlwyd"
  }
]
```

### Get a user

Return the details of a plugin module instance

#### URL

`/api/user/{username}`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`username`: username to return, mandatory
`source`: user module instance to look for the user, optional, if not set look on all instances

#### Success response

Code 200

Content

```javascript
{
  username: string, mandatory
  scope:[
    scope_value: string, mandatory, array can be empty
  ],
  enabled: boolean, mandatory
  name: string, optional
  email: string, optional
  other values: string or array of strings, optional, depends on what's returned by the module instance
}
```

Example

```javascript
{
  username: "user1",
  scope: [
    "g_profile",
    "scope1",
    "scope2"
  ],
  enabled: true,
  name: "Dave Lopper",
  email: "user1@glewlwyd",
  alias: [
    "dev",
    "plop"
  ]
}
```

Code 404

User not found

### Add a new user

#### URL

`/api/user/`

#### Method

`POST`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`source`: user module instance to look for the user, optional, if not set, the first instance in write mode in order rank will host the new user

#### Body Parameters

```javascript
{
  username: string, mandatory
  scope:[
    scope_value: string, mandatory, array can be empty
  ],
  password: string, optional, if not set, the user won't be able to authenticate
  enabled: boolean, optional, default true
  name: string, optional
  email: string, optional
  other values: string or array of strings, optional, depends on the module instance
}
```

#### Success response

Code 200

User added

Code 400

Error input parameters

Content

A javascript array with the error messages

### Update an existing user

#### URL

`/api/user/{username}`

#### Method

`PUT`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`username`: username of the user to update
`source`: user module instance to look for the user, optional, if not set look on all instances

#### Body Parameters

```javascript
{
  username: string, mandatory
  scope:[
    scope_value: string, mandatory, array can be empty
  ],
  enabled: boolean, optional, default true
  name: string, optional
  email: string, optional
  other values: string or array of strings, optional, depends on the module instance
}
```

#### Success response

Code 200

User updated

Code 404

User not found

Code 400

Error input parameters

Content

A javascript array with the error messages

### Delete an existing user

#### URL

`/api/user/{username}`

#### Method

`DELETE`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`username`: username of the user to delete

#### Success response

Code 200

User removed

Code 404

User not found

## Clients management

### Get a list of clients available

Return a list of clients available

#### URL

`/api/client/`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`offset`: number, the offset to start the list, default 0
`limit`: number, the maximal number of elements in the list, default 100
`source`: string, the instance name to limit the result, if not set, all instances will be used
`pattern`: string, the pattern to filter the result

#### Success response

Code 200

Content

```javascript
[{
  client_id: string, mandatory
  scope:[
    scope_value: string, mandatory, array can be empty
  ],
  enabled: boolean, mandatory
  name: string, optional
  description: string, optional
  confidential: boolean, optional
  other values: string or array of strings, optional, depends on what's returned by the module instance
}]
```

Example

```javascript
[
  {
    client_id: "client1",
    scope: [
      "scope1",
      "scope2"
    ],
    enabled: true,
    name: "First client",
    confidential: true,
    redirect_uri: [
      "http://example.com/"
    ]
  },
  {
    client_id: "client2",
    scope: [
      "scope1"
    ],
    enabled: true,
    name: "Second client",
    confidential: false,
    redirect_uri: [
      "http://another.example.com"
    ]
  }
]
```

### Get a client

Return the details of a plugin module instance

#### URL

`/api/client/{client_id}`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`client_id`: client_id to return, mandatory
`source`: client module instance to look for the client, optional, if not set look on all instances

#### Success response

Code 200

Content

```javascript
{
  client_id: string, mandatory
  scope:[
    scope_value: string, mandatory, array can be empty
  ],
  enabled: boolean, mandatory
  name: string, optional
  description: string, optional
  confidential: boolean, optional
  other values: string or array of strings, optional, depends on what's returned by the module instance
}
```

Example

```javascript
{
  client_id: "client1",
  scope: [
    "scope1",
    "scope2"
  ],
  enabled: true,
  name: "First client",
  confidential: true,
  redirect_uri: [
    "http://example.com/"
  ]
}
```

Code 404

Client not found

### Add a new client

#### URL

`/api/client/`

#### Method

`POST`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`source`: client module instance to look for the client, optional, if not set, the first instance in write mode in order rank will host the new client

#### Body Parameters

```javascript
{
  client_id: string, mandatory
  scope:[
    scope_value: string, mandatory, array can be empty
  ],
  password: string, optional, if not set, the client won't be able to authenticate
  enabled: boolean, optional, default true
  name: string, optional
  description: string, optional
  other values: string or array of strings, optional, depends on the module instance
}
```

#### Success response

Code 200

Client added

Code 400

Error input parameters

Content

A javascript array with the error messages

### Update an existing client

#### URL

`/api/client/{client_id}`

#### Method

`PUT`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`client_id`: client_id of the client to update
`source`: client module instance to look for the client, optional, if not set look on all instances

#### Body Parameters

```javascript
{
  client_id: string, mandatory
  scope:[
    scope_value: string, mandatory, array can be empty
  ],
  password: string, optional, if not set, the client won't be able to authenticate
  enabled: boolean, optional, default true
  name: string, optional
  description: string, optional
  other values: string or array of strings, optional, depends on the module instance
}
```

#### Success response

Code 200

Client updated

Code 404

Client not found

Code 400

Error input parameters

Content

A javascript array with the error messages

### Delete an existing client

#### URL

`/api/client/{client_id}`

#### Method

`DELETE`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`client_id`: client_id of the client to delete

#### Success response

Code 200

Client removed

Code 404

Client not found

## Scopes management

### Get a list of scopes available

Return a list of scopes available

#### URL

`/api/scope/`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`offset`: number, the offset to start the list, default 0
`limit`: number, the maximal number of elements in the list, default 100
`source`: string, the instance name to limit the result, if not set, all instances will be used
`pattern`: string, the pattern to filter the result

#### Success response

Code 200

Content

```javascript
[{
  name: string, mandatory
  display_name: string, mandatory
  description: string, mandatory
  password_required: boolean, mandatory
  scheme: {
    group_name: [
      {
        scheme_type: module type, string, mandatory
        scheme_name: module name, string, mandatory
        scheme_display_name: module display name, string, mandatory
      }
    ]
  }
}]
```

Example

```javascript
[
  {
    name: "scope1",
    display_name: "First scope",
    description: "The first scope",
    password_required: true,
    scheme: {
      group1: [
        {
          scheme_type: "mock",
          scheme_name: "mock1",
          scheme_display_name: "First mock scheme"
        },
        {
          scheme_type: "mock",
          scheme_name: "mock2",
          scheme_display_name: "Second mock scheme"
        }
      ]
    }
  },
  {
    name: "scope2",
    scope: [
      "scope1"
    ],
    enabled: true,
    name: "Second scope",
    confidential: false,
    redirect_uri: [
      "http://another.example.com"
    ]
  }
]
```

### Get a scope

Return the details of a plugin module instance

#### URL

`/api/scope/{name}`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name to return, mandatory
`source`: scope module instance to look for the scope, optional, if not set look on all instances

#### Success response

Code 200

Content

```javascript
{
  name: string, mandatory
  scope:[
    scope_value: string, mandatory, array can be empty
  ],
  enabled: boolean, mandatory
  name: string, optional
  description: string, optional
  confidential: boolean, optional
  other values: string or array of strings, optional, depends on what's returned by the module instance
}
```

Example

```javascript
{
  name: "scope1",
  scope: [
    "scope1",
    "scope2"
  ],
  enabled: true,
  name: "First scope",
  confidential: true,
  redirect_uri: [
    "http://example.com/"
  ]
}
```

Code 404

Scope not found

### Add a new scope

#### URL

`/api/scope/`

#### Method

`POST`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`source`: scope module instance to look for the scope, optional, if not set, the first instance in write mode in order rank will host the new scope

#### Body Parameters

```javascript
{
  name: string, mandatory
  scope:[
    scope_value: string, mandatory, array can be empty
  ],
  password: string, optional, if not set, the scope won't be able to authenticate
  enabled: boolean, optional, default true
  name: string, optional
  description: string, optional
  other values: string or array of strings, optional, depends on the module instance
}
```

#### Success response

Code 200

Scope added

Code 400

Error input parameters

Content

A javascript array with the error messages

### Update an existing scope

#### URL

`/api/scope/{name}`

#### Method

`PUT`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the scope to update
`source`: scope module instance to look for the scope, optional, if not set look on all instances

#### Body Parameters

```javascript
{
  name: string, mandatory
  scope:[
    scope_value: string, mandatory, array can be empty
  ],
  password: string, optional, if not set, the scope won't be able to authenticate
  enabled: boolean, optional, default true
  name: string, optional
  description: string, optional
  other values: string or array of strings, optional, depends on the module instance
}
```

#### Success response

Code 200

Scope updated

Code 404

Scope not found

Code 400

Error input parameters

Content

A javascript array with the error messages

### Delete an existing scope

#### URL

`/api/scope/{name}`

#### Method

`DELETE`

#### Security

User with scope `g_admin` authorized.

#### URL Parameters

`name`: name of the scope to delete

#### Success response

Code 200

Scope removed

Code 404

Scope not found

## User authentication

### Authenticate a user with password

#### URL

`/api/auth`

#### Method

`POST`

#### Body Parameters

```javascript
{
  username: string, mandatory
  password: string, mandatory
}
```

#### Success response

Code 200

User authenticated

Code 400

Error input parameters

Code 401

Authentication failure

### Authenticate a user with an authentication scheme

#### URL

`/api/auth`

#### Method

`POST`

#### Body Parameters

```javascript
{
  username: string, mandatory
  scheme_type: string, mandatory
  scheme_name: string: mandatory
  value: object, mandatory, content depends on the scheme
}
```

#### Success response

Code 200

User authenticated

Code 400

Error input parameters

Code 401

Authentication failure

### Trigger a scheme

#### URL

`/api/auth/scheme/trigger`

#### Method

`POST`

#### Body Parameters

```javascript
{
  username: string, mandatory
  scheme_type: string, mandatory
  scheme_name: string: mandatory
  value: object, mandatory, content depends on the scheme
}
```

#### Success response

Code 200

User authenticated

Code 400

Error input parameters

Code 401

Authentication failure

### Change current user with another user authenticated in this session

#### URL

`/api/auth`

#### Method

`POST`

#### Body Parameters

```javascript
{
  username: string, mandatory
}
```

#### Success response

Code 200

Current user changed

Code 400

Error input parameters

Code 401

Authentication failure

## User profile

### Get list of connected profiles

The first element in the returned array is the current user

#### URL

`/api/profile`

#### Method

`GET`

#### Security

User with scope `g_profile` authorized.

#### Success response

Code 200

Content

```javascript
[
  {
    username: string, mandatory
    scope:[
      scope_value: string, mandatory, array can be empty
    ],
    name: string, optional
    email: string, optional
    other values: string or array of strings, optional, depends on what's returned by the module instance for the profile
  }
]
```

Code 401

No enabled authenticated user for this session

### Update current profile

#### URL

`/api/profile`

#### Method

`PUT`

#### Security

User with scope `g_profile` authorized.

#### Body Parameters

```javascript
{
  username: string, mandatory
  name: string, optional
  other values: string or array of strings, optional, depends on what's exptected by the module instance for the profile
}
```

#### Success response

Code 200

User updated

Code 400

Error input parameters

Content

A javascript array with the error messages

### Change user password for current profile

#### URL

`/api/profile/password`

#### Method

`PUT`

#### Security

User with scope `g_profile` authorized.

#### Body Parameters

```javascript
{
  username: string, mandatory, same username as current user
  old_password: string, mandatory
  password: string, mandatory
}
```

#### Success response

Code 200

User password updated

Code 400

Error input parameters

Content

A javascript array with the error messages

### Get sessions for current profile

#### URL

`/api/profile/session`

#### Method

`GET`

#### Security

User with scope `g_profile` authorized.

#### Success response

Code 200

Content

```javascript
[
  {
    session_hash: string,
    user_agent: string,
    issued_for: string,
    expiration: string,
    last_login: string,
    enabled: string
  }
]
```

Code 401

No enabled authenticated user for this session

### Disable a session for current profile

#### URL

`/api/profile/session/{session_hash}`

#### Method

`DELETE`

#### Security

User with scope `g_profile` authorized.

#### Success response

Code 200

Session disabled

Code 401

No enabled authenticated user for this session

### Register an auth scheme for current profile

#### URL

`/api/profile/scheme/register/`

#### Method

`POST`

#### Security

User with scope `g_profile` authorized.

#### Body Parameters

```javascript
{
  username: string, mandatory
  scheme_type: string, mandatory
  scheme_name: string: mandatory
  value: object, mandatory, content depends on the scheme
}
```

#### Success response

Code 200

Scheme registered

Code 400

Error input parameters

Content

A javascript array with the error messages

Code 401

No enabled authenticated user for this session

### Get registration on an auth scheme for current profile

#### URL

`/api/profile/scheme/register/`

#### Method

`PUT`

#### Security

User with scope `g_profile` authorized.

#### Body Parameters

```javascript
{
  username: string, mandatory
  scheme_type: string, mandatory
  scheme_name: string: mandatory
}
```

#### Success response

Code 200

Content

Depends on the scheme

Code 400

Error input parameters

Content

A javascript array with the error messages

Code 401

No enabled authenticated user for this session

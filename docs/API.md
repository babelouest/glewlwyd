# Glewlwyd API description

This document is intended to describe Glewlwyd's core API endpoints. Glewlwyd's core API endpoints are used to manage core functionalities data.

- [Endpoints authentication](#endpoints-authentication)
- [Prefix](#prefix)
- [Content-type](#content-type)
- [Error response](#error-response)
- [Configuratiom](#configuration)
  - [Get server configuration](#get-server-configuration)
- [Plugins and modules management](#plugins-and-modules-management)
  - [Get all modules available](#get-all-modules-available)
  - [Get all user module instances available](#get-all-user-module-instances-available)
  - [Get a user module instance](#get-a-user-module-instance)
  - [Add a new user module instance](#add-a-new-user-module-instance)
  - [Update an existing user module instance](#update-an-existing-user-module-instance)
  - [Delete an existing user module instance](#delete-an-existing-user-module-instance)
  - [Enable or disable an existing user module instance](#enable-or-disable-an-existing-user-module-instance)
  - [Get all client module instances available](#get-all-client-module-instances-available)
  - [Get a client module instance](#get-a-client-module-instance)
  - [Add a new client module instance](#add-a-new-client-module-instance)
  - [Update an existing client module instance](#update-an-existing-client-module-instance)
  - [Delete an existing client module instance](#delete-an-existing-client-module-instance)
  - [Enable or disable an existing client module instance](#enable-or-disable-an-existing-client-module-instance)
  - [Get all user auth scheme module instances available](#get-all-user-auth-scheme-module-instances-available)
  - [Get a user auth scheme module instance](#get-a-user-auth-scheme-module-instance)
  - [Add a new user auth scheme module instance](#add-a-new-user-auth-scheme-module-instance)
  - [Update an existing user auth scheme module instance](#update-an-existing-user-auth-scheme-module-instance)
  - [Delete an existing user auth scheme module instance](#delete-an-existing-user-auth-scheme-module-instance)
  - [Enable or disable an existing user auth scheme module instance](#enable-or-disable-an-existing-user-auth-scheme-module-instance)
  - [Get all plugin module instances available](#get-all-plugin-module-instances-available)
  - [Get a plugin module instance](#get-a-plugin-module-instance)
  - [Add a new plugin module instance](#add-a-new-plugin-module-instance)
  - [Update an existing plugin module instance](#update-an-existing-plugin-module-instance)
  - [Delete an existing plugin module instance](#delete-an-existing-plugin-module-instance)
  - [Enable or disable an existing plugin module instance](#enable-or-disable-an-existing-plugin-module-instance)
- [Users management](#users-management)
  - [Get a list of users available](#get-a-list-of-users-available)
  - [Get a user](#get-a-user)
  - [Add a new user](#add-a-new-user)
  - [Update an existing user](#update-an-existing-user)
  - [Delete an existing user](#delete-an-existing-user)
- [Clients management](#clients-management)
  - [Get a list of clients available](#get-a-list-of-clients-available)
  - [Get a client](#get-a-client)
  - [Add a new client](#add-a-new-client)
  - [Update an existing client](#update-an-existing-client)
  - [Delete an existing client](#delete-an-existing-client)
- [Scopes management](#scopes-management)
  - [Get a list of scopes available](#get-a-list-of-scopes-available)
  - [Get a scope](#get-a-scope)
  - [Add a new scope](#add-a-new-scope)
  - [Update an existing scope](#update-an-existing-scope)
  - [Delete an existing scope](#delete-an-existing-scope)
- [User authentication](#user-authentication)
  - [Authenticate a user with password](#authenticate-a-user-with-password)
  - [Authenticate a user with an authentication scheme](#authenticate-a-user-with-an-authentication-scheme)
  - [Get authorized scopes from a scope list for a user](#get-authorized-scopes-from-a-scope-list-for-a-user)
  - [Trigger a scheme](#trigger-a-scheme)
  - [Change current user with another user authenticated in this session](#change-current-user-with-another-user-authenticated-in-this-session)
- [Grant scopes](#grant-scopes)
  - [Get list of granted scopes for a client by the user](#get-list-of-granted-scopes-for-a-client-by-the-user)
  - [Update granted scope for a client by a user](#update-granted-scope-for-a-client-by-a-user)
- [User profile](#user-profile)
  - [Get list of connected profiles](#get-list-of-connected-profiles)
  - [Update current profile](#update-current-profile)
  - [Change user password for current profile](#change-user-password-for-current-profile)
  - [Delete current profile](#delete-current-profile)
  - [Get list of plugins available](#get-list-of-plugins-available)
  - [Get sessions for current profile](#get-sessions-for-current-profile)
  - [Disable a session for current profile](#disable-a-session-for-current-profile)
  - [Get list of schemes available](#get-list-of-schemes-available)
  - [Register an auth scheme for current profile](#register-an-auth-scheme-for-current-profile)
  - [Get registration on an auth scheme for current profile](#get-registration-on-an-auth-scheme-for-current-profile)
- [Profile delegation](#profile-delegation)
  - [Update profile by delegation](#update-profile-by-delegation)
  - [Get sessions for profile by delegation](#get-sessions-for-profile-by-delegation)
  - [Disable a session for a profile by delegation](#disable-a-session-for-a-profile-by-delegation)
  - [Get list of plugins available by delegation](#get-list-of-plugins-available-by-delegation)
  - [Get list of schemes available by delegation](#get-list-of-schemes-available-by-delegation)
  - [Register an auth scheme for a profile by delegation](#register-an-auth-scheme-for-a-profile-by-delegation)
  - [Get registration on an auth scheme for a profile by delegation](#get-registration-on-an-auth-scheme-for-a-profile-by-delegation)
- [Authentication Scheme APIs](#authentication-scheme-apis)
  - [Mock authentication scheme](#mock-authentication-scheme)
  - [E-mail OTP authentication scheme](#e-mail-otp-authentication-scheme)
  - [HOTP/TOTP authentication scheme](#hotptotp-authentication-scheme)
  - [Password authentication scheme](#password-authentication-scheme)
  - [Webauthn authentication scheme](#webauthn-authentication-scheme)
  - [TLS Certificate authentication scheme](#tls-certificate-authentication-scheme)

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

## Configuration

### Get server configuration

This endpoint is the only one accessible directly from the root of the server.

#### URL

`/config`

#### Method

`GET`

#### Success response

Code 200

Content

```javascript
{
  "api_prefix": string, prefix to access the APIs
  "admin_scope": string, name of the admin scope
  "profile_scope": string, name of the profile scope
}
```

Example

```javascript
{
  "api_prefix":"api",
  "admin_scope":"g_admin",
  "profile_scope":"g_profile"
}
```

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
{
  "user":[
    {
      "name":"http",
      "display_name":"HTTP auth backend user module",
      "description":"Module to store users in the database",
      "parameters":{
        "url":{
          "type":"string",
          "mandatory":true
        },
        "check-server-certificate":{
          "type":"boolean",
          "mandatory":false,
          "default":true
        },
        "default-scope":{
          "type":"array",
          "mandatory":true,
          "values":["string"]
        }
      }
    },
    {
      "name":"mock",
      "display_name":"Mock user module",
      "description":"Mock user module for glewlwyd tests",
      "parameters":{
        "username-prefix":{
          "type":"string",
          "mandatory":false
        },
        "password":{
          "type":"string",
          "mandatory":false
        }
      }
    }
  ],
  "client":[
    {
      "name":"mock",
      "display_name":"Mock scheme module",
      "description":"Mock scheme module for glewlwyd tests",
      "parameters":{
        "username-prefix":{
          "type":"string",
          "mandatory":false
        },
        "password":{
          "type":"string",
          "mandatory":false
        }
      }
    },
    {
      "name":"database",
      "display_name":"Database backend client module",
      "description":"Module to store clients in the database",
      "parameters":{
        "use-glewlwyd-connection":{
          "type":"boolean",
          "mandatory":true
        },
        "connection-type":{
          "type":"list",
          "values":[
            "sqlite","mariadb","postgre"
          ],
          "mandatory":false
        },
        "sqlite-dbpath":{
          "type":"string",
          "mandatory":false
        },
        "mariadb-host":{
          "type":"string",
          "mandatory":false
        },
        "mariadb-client":{
          "type":"string",
          "mandatory":false
        },
        "mariadb-password":{
          "type":"string",
          "mandatory":false
        },
        "mariadb-dbname":{
          "type":"string",
          "mandatory":false
        },
        "mariadb-port":{
          "type":"number",
          "mandatory":false
        },
        "postgre-conninfo":{
          "type":"string",
          "mandatory":false
        },
        "data-format":{
          "field-name":{
            "multiple":{
              "type":"boolean",
              "default":false
            },
            "read":{
              "type":"boolean",
              "default":true
            },
            "write":{
              "type":"boolean",
              "default":true
            },
            "profile-read":{
              "type":"boolean",
              "default":false
            },
            "profile-write":{
              "type":"boolean",
              "default":false
            }
          }
        }
      }
    }
  ],
  "scheme":[
    {
      "name":"mock",
      "display_name":"Mock",
      "description":"Mock scheme module for glewlwyd tests",
      "parameters":{
        "mock-value":{
          "type":"string",
          "mandatory":true
        }
      }
    },
    {
      "name":"retype-password",
      "display_name":"Short session password",
      "description":"Glewlwyd authentification via user password with a short session duration",
      "parameters":{
      }
    }
  ],
  "plugin":[
    {
      "name":"mock",
      "display_name":"Mock plugin",
      "description":"Mock plugin description",
      "parameters":{
      }
    },
    {
      "name":"oauth2-glewlwyd",
      "display_name":"Glewlwyd OAuth2 plugin",
      "description":"Plugin for legacy Glewlwyd OAuth2 workflow",
      "parameters":{
        "jwt-type":{
          "type":"list",
          "mandatory":true,
          "values":["rsa","ecdsa","sha"]
        },
        "jwt-key-size":{
          "type":"string",
          "mandatory":true,
          "values":["256","384","512"]
        },
        "key":{
          "type":"string",
          "mandatory":true
        },
        "cert":{
          "type":"string",
          "mandatory":true
        },
        "access-token-duration":{
          "type":"number",
          "mandatory":true
        },
        "refresh-token-duration":{
          "type":"number",
          "mandatory":true
        },
        "code-token-duration":{
          "type":"number",
          "mandatory":true
        },
        "refresh-token-rolling":{
          "type":"boolean",
          "default":false
        },
        "auth-type-code-enabled":{
          "type":"boolean",
          "mandatory":true
        },
        "auth-type-implicit-enabled":{
          "type":"boolean",
          "mandatory":true
        },
        "auth-type-password-enabled":{
          "type":"boolean",
          "mandatory":true
        },
        "auth-type-client-enabled":{
          "type":"boolean",
          "mandatory":true
        },
        "auth-type-refresh-enabled":{
          "type":"boolean",
          "mandatory":true
        },
        "scope":{
          "type":"array",
          "mandatory":false,
          "format":{
            "type":"string",
            "mandatory":true
          },
          "rolling-refresh":{
            "type":"boolean",
            "mandatory":false
          }
        }
      }
    }
  ]
}
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
[
  {
    "module":"mock",
    "name":"mock",
    "display_name":"Mock user module",
    "order_rank":0,
    "parameters":{
      "username-prefix":"",
      "password":"password"
    },
    "readonly":false,
    "enabled":true
  }
]
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
{
  "module":"mock",
  "name":"mock",
  "display_name":"Mock user module",
  "order_rank":0,
  "parameters":{
    "username-prefix":"",
    "password":"password"
  },
  "readonly":false,
  "enabled":true
}
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

A JSON array with the error messages

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

A JSON array with the error messages

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
`action`: either `enable` or `disable` or `reset`

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
[
  {
    "module":"mock",
    "name":"mock",
    "display_name":"Mock client module",
    "order_rank":0,
    "parameters":{
      "username-prefix":"",
      "password":"password"
    },
    "readonly":false,
    "enabled":true
  }
]
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
{
  "module":"mock",
  "name":"mock",
  "display_name":"Mock client module",
  "order_rank":0,
  "parameters":{
    "username-prefix":"",
    "password":"password"
  },
  "readonly":false,
  "enabled":true
}
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

A JSON array with the error messages

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

A JSON array with the error messages

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
`action`: either `enable` or `disable` or `reset`

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
[
  {
    "module":"mock",
    "name":"mock_scheme_42",
    "display_name":"Mock 42",
    "expiration":600,
    "max_use":0,
    "parameters":{
      "mock-value":"42"
    },
    "allow_user_register":true,
    "enabled":true
  }
]
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
{
  "module":"mock",
  "name":"mock_scheme_42",
  "display_name":"Mock 42",
  "expiration":600,
  "max_use":0,
  "parameters":{
    "mock-value":"42"
  },
  "allow_user_register":true,
  "enabled":true
}
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

A JSON array with the error messages

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

A JSON array with the error messages

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
`action`: either `enable` or `disable` or `reset`

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
[
  {
    "module":"oauth2-glewlwyd",
    "name":"glwd",
    "display_name":"OAuth2 Glewlwyd plugin",
    "parameters":{
      "jwt-type":"sha",
      "jwt-key-size":"256",
      "key":"secret",
      "access-token-duration":3600,
      "refresh-token-duration":1209600,
      "code-duration":600,
      "refresh-token-rolling":true,
      "auth-type-code-enabled":true,
      "auth-type-implicit-enabled":true,
      "auth-type-password-enabled":true,
      "auth-type-client-enabled":true,
      "auth-type-refresh-enabled":true,
      "scope":[
        {
          "name":"g_profile",
          "refresh-token-rolling":true
        },
        {
          "name":"scope1",
          "refresh-token-rolling":true
        },
        {
          "name":"scope2",
          "refresh-token-rolling":false,
          "refresh-token-duration":7200
        }
      ]
    },
    "enabled":true
  }
]
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
{
  "module":"oauth2-glewlwyd",
  "name":"glwd",
  "display_name":"OAuth2 Glewlwyd plugin",
  "parameters":{
    "jwt-type":"sha",
    "jwt-key-size":"256",
    "key":"secret",
    "access-token-duration":3600,
    "refresh-token-duration":1209600,
    "code-duration":600,
    "refresh-token-rolling":true,
    "auth-type-code-enabled":true,
    "auth-type-implicit-enabled":true,
    "auth-type-password-enabled":true,
    "auth-type-client-enabled":true,
    "auth-type-refresh-enabled":true,
    "scope":[
      {
        "name":"g_profile",
        "refresh-token-rolling":true
      },
      {
        "name":"scope1",
        "refresh-token-rolling":true
      },
      {
        "name":"scope2",
        "refresh-token-rolling":false,
        "refresh-token-duration":7200
      }
    ]
  },
  "enabled":true
}
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

A JSON array with the error messages

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

A JSON array with the error messages

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
`action`: either `enable` or `disable` or `reset`

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

A JSON array with the error messages

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

A JSON array with the error messages

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

A JSON array with the error messages

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

A JSON array with the error messages

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
`limit`: number, the maximal number of elements in the list, default 100, if limit is explicitly set to 0, no limit
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

A JSON array with the error messages

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

A JSON array with the error messages

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

### Get authorized scopes from a scope list for a user

#### URL

`/auth/scheme/`

#### Method

`GET`

#### Security

Valid user session.

#### URL Parameters

`scope`: list of scopes requested, separated by spaces

#### Success response

Code 200

Content

```javascript
{
  "scope_name": { // Name of the scope
    "password_required": boolean, wether the password is required to access this scope
    "schemes":{
      "group_name": [
        {
          "scheme_type": string, module name of the scheme
          "scheme_name": string, module instance name
          "scheme_display_name": string, mudule instance display name
          "scheme_authenticated": boolean, wether this scheme is authenticated for this user on this session
          "scheme_registered": boolean wether this scheme is registered for this user
        }
      ]
    },
    "display_name": string, display name of the scope
    "description":string, description of the scope
    "password_authenticated": boolean, wether this scope is authenticated for this user on this session
    "available": boolean, wether this scope is available for this user
  }
}
```

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

## Grant scopes

### Get list of granted scopes for a client by the user

#### URL

`/api/auth/grant/{client_id}/{scope_list}`

#### Method

`GET`

#### Security

User with scope `g_profile` authorized.

#### URL Parameters

`client_id`: client_id of the client
`scope_list`: list of scopes separated by a space

#### Success response

Code 200

Content

```javascript
{
  "client":{
    "client_id": string, client_id
    "name": string, client name
  },
  "scope":[
    {
      "name": string, scope name
      "display_name": string, scope display name
      "description": string, scope description
      "password_required": boolean, wether this scope has password required to login
      "granted": boolean, wether this scope is granted to this client by this user
    }
  ]
}
```

Code 401

No enabled authenticated user for this session

### Update granted scope for a client by a user

#### URL

`/auth/grant/{client_id}/`

#### Method

`PUT`

#### Security

User with scope `g_profile` authorized.

#### Body Parameters

```javascript
{
  "scope": string, scope list granted to this client separated by a comma, set the list empty to remove all grant
}
```

#### Success response

Code 200

User updated

Code 400

Error input parameters

Content

A JSON array with the error messages

## User profile

### Get list of connected profiles

The first element in the returned array is the current user

#### URL

`/api/profile_list`

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

A JSON array with the error messages

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

A JSON array with the error messages

### Delete current profile

#### URL

`/api/profile/`

#### Method

`DELETE`

#### Security

User with scope `g_profile` authorized.

#### Success response

Code 200

Profile succesfully removed

Code 403

The user is not allowed to remove its own profile.

### Get list of plugins available

#### URL

`/api/profile/plugin`

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
    "module": string, plugin type
    "name": string, plugin instance name
    "display_name": string, plugin instance display name
  }
]
```

Code 401

No enabled authenticated user for this session

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

### Get list of schemes available

#### URL

`/api/profile/scheme`

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
    "module": string, module name of the scheme
    "name": string, module instance name
    "display_name": string, module instance display name
    "expiration": number, duration of an authentication with this scheme
    "max_use": number, number of thime this scheme authenticated can be used in a plugin
    "allow_user_register": boolean, wether the user can register this scheme
    "enabled": boolean
  }
]
```

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

A JSON array with the error messages

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

A JSON array with the error messages

Code 401

No enabled authenticated user for this session

## Profile delegation

All those endpoints are available for an administrator in order to access and update a user's profile and its schemes registration

### Update profile by delegation

#### URL

`/api/delegate/profile?username=<username>`

#### Method

`PUT`

#### Security

Admin with scope `g_admin` authorized.

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

A JSON array with the error messages

### Get sessions for profile by delegation

#### URL

`/api/delegate/profile/session?username=<username>`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

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

No enabled authenticated admin for this session

### Disable a session for a profile by delegation

#### URL

`/api/delegate/profile/session/{session_hash}?username=<username>`

#### Method

`DELETE`

#### Security

User with scope `g_admin` authorized.

#### Success response

Code 200

Session disabled

Code 401

No enabled authenticated user for this session

### Get list of plugins available by delegation

#### URL

`/api/delegate/profile/plugin?username=<username>`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### Success response

Code 200

Content

```javascript
[
  {
    "module": string, plugin type
    "name": string, plugin instance name
    "display_name": string, plugin instance display name
  }
]
```

Code 401

No enabled authenticated user for this session

### Get list of schemes available by delegation

#### URL

`/api/delegate/profile/scheme?username=<username>`

#### Method

`GET`

#### Security

User with scope `g_admin` authorized.

#### Success response

Code 200

Content

```javascript
[
  {
    "module": string, module name of the scheme
    "name": string, module instance name
    "display_name": string, module instance display name
    "expiration": number, duration of an authentication with this scheme
    "max_use": number, number of thime this scheme authenticated can be used in a plugin
    "allow_user_register": boolean, wether the user can register this scheme
    "enabled": boolean
  }
]
```

Code 401

No enabled authenticated user for this session

### Register an auth scheme for a profile by delegation

#### URL

`/api/delegate/profile/scheme/register/?username=<username>`

#### Method

`POST`

#### Security

User with scope `g_admin` authorized.

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

A JSON array with the error messages

Code 401

No enabled authenticated user for this session

### Get registration on an auth scheme for a profile by delegation

#### URL

`/api/delegate/profile/scheme/register/?username=<username>`

#### Method

`PUT`

#### Security

User with scope `g_admin` authorized.

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

A JSON array with the error messages

Code 401

No enabled authenticated user for this session

## Authentication Scheme APIs

This chapter will describe the specific paramters for the authentication schemes.

The following APIs will be further explained for each scheme:

- Register scheme: `POST` `/api/profile/scheme/register/`
- Get scheme registration: `PUT` `/api/profile/scheme/register/`
- Trigger scheme: `POST` `/api/auth/scheme/trigger`
- Authentication using scheme: `POST` `/api/auth`

For each APIs, the request and/or response body format will be described. This documentation is an addendum to the generic API documentation above.

### Mock authentication scheme

This scheme exist for tests use only, it simply is an authentication scheme that will behave as a normal scheme and implements all the functions to help designing and programming Glewlwyd.

#### Register scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "mock"
  scheme_name: string: mandatory
  value: {
    register: boolean, mandatory
  }
}
```

Set the parameter `value.register` to `true` or `false` to enable or disable the scheme for the user.

#### Get scheme registration

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "mock"
  scheme_name: string: mandatory
}
```

##### Response body format

```javascript
boolean
```

The response value will be `true` or `false` depending on the scheme registration status.

#### Trigger scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "mock"
  scheme_name: string: mandatory
  value: {} empty object, mandatory
}
```

##### Response body format

```javascript
{
  code: string, will contain the mock value expected to authenticate the user
}
```

#### Authentication using scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "mock"
  scheme_name: string: mandatory
  value: {
    code: string, mandatory
  }
}
```

### E-mail OTP authentication scheme

This authentication scheme sends an one-time password to the e-mail of the user and awaits for the user to retype the password in the login page. Therefore, no registration is possible for the user, and the get registration API will return a HTTP status 200 if the user has an e-mail address and 400 otherwise.

#### Trigger scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "email"
  scheme_name: string: mandatory
  value: {} empty object, mandatory
}
```

#### Authentication using scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "email"
  scheme_name: string: mandatory
  value: {
    code: string, mandatory
  }
}
```

### HOTP/TOTP authentication scheme

#### Register scheme

##### Request body format

Request a random secret for a new OTP to the server. The random secret will be returned in a base32 string format.

```javascript
{
  username: string, mandatory
  scheme_type: "otp"
  scheme_name: string: mandatory
  value: {
    generate-secret: true
  }
}
```

Delete current OTP setting for the current user

```javascript
{
  username: string, mandatory
  scheme_type: "otp"
  scheme_name: string: mandatory
  value: {
    type: "NONE"
  }
}
```

Setup current OTP setting as HOTP

```javascript
{
  username: string, mandatory
  scheme_type: "otp"
  scheme_name: string: mandatory
  value: {
    type: "HOTP"
    secret: base32 string, mandatory
    moving_factor: positive integer, optional
  }
}
```

Setup current OTP setting as HT
```javascript
{
  username: string, mandatory
  scheme_type: "otp"
  scheme_name: string: mandatory
  value: {
    type: "HOTP"
    secret: base32 string, mandatory
    time_step_size: non zero positive integer, optional
  }
}
```

#### Get scheme registration

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "otp"
  scheme_name: string: mandatory
}
```

##### Response body format

```javascript
{
  digits: integer, number of digits required on the authentication code
  issuer: string, will contain the issuer value (a metadata)
  hotp-allow: boolean, set to true if the user is allowed to register a HOTP
  totp-allow: boolean, set to true if the user is allowed to register a TOTP
  type: string, will contain one of the following values: "NONE", "HOTP" or "TOTP"
  secret: string, secret registered if a scheme is registered
  moving_factor: integer
  time_step_size: integer
}
```

Example, for a TOTP registration:

```javascript
{
  digits: 6,
  issuer: "https://glewlwyd.tld",
  hotp-allow: true,
  totp-allow: true,
  type: "TOTP",
  secret: "abcd1234===",
  moving_factor: 0
  time_step_size: 30
}
```

#### Trigger scheme

N/A

#### Authentication using scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "otp"
  scheme_name: string: mandatory
  value: string, mandatory
}
```

### Password authentication scheme

This authentication scheme simply uses the password field of the user - if it's possible - therefore, this scheme simply has an authentication API implemented

#### Register scheme

N/A

#### Get scheme registration

N/A

#### Trigger scheme

N/A

#### Authentication using scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "otp"
  scheme_name: string: mandatory
  value: {
    password: string, mandatory
  }
}
```

### Webauthn authentication scheme

This scheme is based on the [Webauthn API](https://w3c.github.io/webauthn/).

#### Register scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "webauthn"
  scheme_name: string: mandatory
  value: {
    register: string, values available are "new-credential", "register-credential", "remove-credential", "disable-credential", "enable-credential", "edit-credential", "trigger-assertion" or "validate-assertion"
    // Other values depending on the register value
  }
}
```

- Request body format for `register: "new-credential"`

```javascript
{
  username: string, mandatory
  scheme_type: "webauthn"
  scheme_name: string: mandatory
  value: {
    register: "new-credential"
  }
}
```

- Response body format for `register: "new-credential"`

```javascript
{
  session: string
  challenge: string
  pubKey-cred-params: array of string, list of public key formats accepted
  attestation-required: boolean, set to false if scheme accepts fmt type "none"
  user: {
    id: string
    name: string
  }
  rpId: string, relaying part id
}
```

- Request body format for `register: "register-credential"`

```javascript
{
  username: string, mandatory
  scheme_type: "webauthn"
  scheme_name: string: mandatory
  value: {
    register: "register-credential",
    session: string, must be the session id sent in the previous "register-credential"
    credential: { // The credential object is returned by the Webauthn API call `navigator.credentials.create` in the profile page
      rawId: string
      response: {
        clientDataJSON: string
        attestationObject: string
      }
    }
  }
}
```

- Response body format for `register: "register-credential"`

HTTP Status 200 on success, 401 on error registration, 400 on error parameters, 404 on error in the session id, 500 otherwise

- Request body format for `register: "remove-credential"`, `register: "disable-credential"`, `register: "enable-credential"`

```javascript
{
  username: string, mandatory
  scheme_type: "webauthn"
  scheme_name: string: mandatory
  value: {
    register: "remove-credential" || "disable-credential" || enable-credential",
    credential_id: string, must a valid `credential_id` returned by the get_gegister API
  }
}
```

- Response body format for `register: "register-credential"`

HTTP Status 200 on success, 400 on error parameters, 404 on error in the credential_id, 500 otherwise

- Request body format for `register: "trigger-assertion"`

```javascript
{
  username: string, mandatory
  scheme_type: "webauthn"
  scheme_name: string: mandatory
  value: {
    register: "trigger-assertion"
  }
}
```

- Response body format for `register: "trigger-assertion"`

```javascript
{
  allowCredentials: array of strings, list of credentials accepted for the user
  session: string
  challenge: string
  user: {
    id: string
    name: string
  }
  rpId: string, relaying part id
}
```

- Request body format for `register: "validate-assertion"`

```javascript
{
  username: string, mandatory
  scheme_type: "webauthn"
  scheme_name: string: mandatory
  value: {
    register: "validate-assertion",
    session: string, must be the session id sent in the previous "register-credential"
    credential: { // The credential object is returned by the Webauthn API call `navigator.credentials.get` in the profile page
      rawId: string
      response: {
        clientDataJSON: string
        authenticatorData: string
      }
    }
  }
}
```

- Response body format for `register: "register-credential"`

HTTP Status 200 on success, 401 on error registration, 400 on error parameters, 404 on error in the session id, 500 otherwise

#### Get scheme registration

##### Response body format

```javascript
[
  {
    credential_id: string, identifier of the credential
    name: string, display name of the credential
    created_at: integer, UNIX epoch time where the credential was created
    status: string, status of the credential, values available are "registered" or "disabled"
  }
]
```

#### Trigger scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "webauthn"
  scheme_name: string: mandatory
  value: {}
}
```

##### Response body format

```javascript
{
  allowCredentials: array of strings, list of credentials accepted for the user, can be a fake list depending on the scheme configuration and the username requested
  session: string
  challenge: string
  user: {
    id: string
    name: string
  }
  rpId: string, relaying part id
}
```

#### Authentication using scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "webauthn"
  scheme_name: string: mandatory
  value: {
    register: "validate-assertion",
    session: string, must be the session id sent in the previous "register-credential"
    credential: { // The credential object is returned by the Webauthn API call `navigator.credentials.get` in the profile page
      rawId: string
      response: {
        clientDataJSON: string
        authenticatorData: string
      }
    }
  }
}
```

### TLS Certificate authentication scheme

This authentication scheme is based on TLS certificate authentication. The first level of authentication is provided by the TLS layer deep down the application, therefore a user can't authenticate with an invalid certificate or a certificate not provided by the configured CA. The scheme module is used to integrate the auth result in Glewlwyd's authentication process with the session, and is also used to manage registered certificates and emit new certificates if possible.

To successfully authenticate a user in Glewlwyd's process using the TLS certificate, the used certificate must be valid for the TLS layer AND must be previously regostered in the user's authorized certificate list.

#### Register scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "certificate"
  scheme_name: string: mandatory
  value: {
    register: string, values available are "test-certificate", "upload-certificate", "use-certificate", "request-certificate", "toggle-certificate" or "delete-certificate"
    // Other values depending on the register value
  }
}
```

- Request body format for `register: "test-certificate"`

```javascript
{
  username: string, mandatory
  scheme_type: "certificate"
  scheme_name: string: mandatory
  value: {
    register: "test-certificate"
  }
}
```

- Response for `register: "test-certificate"`

HTTP Status 200 on success, 401 on test error, 400 on error parameters, 500 otherwise

- Request body format for `register: "upload-certificate"`

```javascript
{
  username: string, mandatory
  scheme_type: "certificate"
  scheme_name: string: mandatory
  value: {
    register: "upload-certificate"
    x509: string, a X509 certificate in PEM format
  }
}
```

- Response for `register: "upload-certificate"`

HTTP Status 200 on success, 400 on error parameters, 500 otherwise

- Request body format for `register: "use-certificate"`

This register action uses the certificate currently used in the TLS layer.

```javascript
{
  username: string, mandatory
  scheme_type: "certificate"
  scheme_name: string: mandatory
  value: {
    register: "use-certificate"
  }
}
```

- Response for `register: "upload-certificate"`

HTTP Status 200 on success, 400 on error parameters, 500 otherwise

- Request body format for `register: "request-certificate"`

This register action returns a `PKCS#12` file in DER format encoded in base64 with a random generated password to unlock the provided file.

```javascript
{
  username: string, mandatory
  scheme_type: "certificate"
  scheme_name: string: mandatory
  value: {
    register: "request-certificate"
  }
}
```

- Response body format for `register: "request-certificate"`

```javascript
{
  p12: string, PKCS#12 file in DER format encoded in base64
  password: string, used to unlck the PKCS#12 file
}
```

- Request body format for `register: "toggle-certificate"`

This register action enable or disable a registered certificate

```javascript
{
  username: string, mandatory
  scheme_type: "certificate"
  scheme_name: string: mandatory
  value: {
    register: "toggle-certificate"
    certificate_id: string, a certificate_id registered to the user, mandatory
    enabled: boolean, set the status to enabled or disabled for the certificate
  }
}
```

- Request body format for `register: "delete-certificate"`

This register action deletes a registered certificate

```javascript
{
  username: string, mandatory
  scheme_type: "certificate"
  scheme_name: string: mandatory
  value: {
    register: "delete-certificate"
    certificate_id: string, a certificate_id registered to the user, mandatory
  }
}
```

#### Get scheme registration

##### Response body format

```javascript
[
  {
    credential_id: string, identifier of the certificate
    certificate_dn: DN of the certificate
    certificate_issuer_dn: DN Of the issuer of the certificate
    activation: integer, UNIX Epoch time where the certificate was activated
    expiration: integer, UNIX Epoch time where the certificate will expire
    last_used: integer, UNIX Epoch time when the certificate was last succesfully used to authenticate a user, optional
    last_user_agent: string, value of the user-agent when the certificate was last succesfully used to authenticate a user, optional
    enabled: boolean
  }
]
```

#### Trigger scheme

N/A

#### Authentication using scheme

##### Request body format

```javascript
{
  username: string, mandatory
  scheme_type: "certificate"
  scheme_name: string: mandatory
  value: {}
}
```

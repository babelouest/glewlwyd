# Glewlwyd Client Module LDAP Backend documentation

![mod-user-database-1](screenshots/mod-user-ldap.png)

The database backend uses a LDAP service to store information and passwords for clients.

## Installation

In the administration page, go to `Parameters/Clients data sources` and add a new client module by clicking on the `+` button. In the modal, enter a name and a display name (the name must be unique among all client backend instances).
Select the type `LDAP backend client module` in the Type dropdown button.

Below is the definition of all parameters.

### Name

Name (identifier) of the module instance, must be unique among all the client backend module instances, even of a different type.

### Display name

Name of the instance displayed to the client.

### Read only

Check this option if you want to use this backend as read-only. All client properties such as e-mail, name, password, scopes can't be modifier with Glewlwyd, even administrators.

### Connection URI

URI to connect to the LDAP service, ex: ldaps://ldap.example.com/

### Connection DN

DN used to acces the LDAP service. The DN must have write access if you want to use this backend in write mode.

### Connection password

Password to use with the `Connection DN`.

### Search page size

Page size to list clients in this backend. This option must be lower than the maximum of results that the LDAP service can send.

### Search base

Base DN to look for clients.

### Search scope

Search scope on the LDAP Base DN. Values available are `one`, `subtree`, `children`.

### Search filter

Filter to apply when performing a search of clients.

### Client ID property

Client ID of the client. This property will be used to build the search filter on a client connection.
You can specify multiple values by separating them with a comma `,`. On read mode, the first value will be used, on write mode, all values will be used.

### Name property

Name of the client.
You can specify multiple values by separating them with a comma `,`. On read mode, the first value will be used, on write mode, all values will be used.

### Scope property

Scopes available for the client. The LDAP property must store multiple values.
You can specify multiple values by separating them with a comma `,`. On read mode, the first value will be used, on write mode, all values will be used.

### Description property

Property used to store the client description value.
You can specify multiple values by separating them with a comma `,`. On read mode, the first value will be used, on write mode, all values will be used.

### Confidential property

Property used to store the client confidential flag value. The value available are "0" (non confidential client) and "1" (confidential client).
You can specify multiple values by separating them with a comma `,`. On read mode, the first value will be used, on write mode, all values will be used.

### Password property.

Property used to store the client password. This property is not used if the instance is in read-only mode.
You can specify multiple values by separating them with a comma `,`. On read mode, the first value will be used, on write mode, all values will be used.

### Algorithm

Algorithm used to hash the client password. This property is not used if the instance is in read-only mode.

### rdn property

This property is mandatory to store the rdn property. This property is not used if the instance is in read-only mode.
You can specify multiple values by separating them with a comma `,`.

### Object class property for a new client

This value will contain all the object class values when Glewlwyd will create new clients in the LDAP backend. Values must be separated with a comme `,`.

### Specific data format

This section allows to specify new properties for the client. The properties may be available for schemes, plugins, in the admin page or in the profile page. By default, when you add a new client backend, the properties `redirect_uri` and `authorization_type` are added with multiple values and read/write modes.

#### Property

Property name, ex: `phone`, `address`, `human`, etc.

#### LDAP Property

Corresponding LDAP property name.

#### Multiple values

If this option is checked, the property values will be available as an array of string values, otherwise a single string value.

### Scope field property

This section allows to specify a correspondance between a Glewlwyd scope and a value in the scope property. The main goal is to use an existing LDAP service whose clients have property that can be related to scopes (group names, etc.). For example, the group name value `accounting` will correspond to the scope `mail`.

#### LDAP value

LDAP value that must match.

#### Corresponding scope

Name of the scope that will be returned. This value must be an existing scope name.

#### Match

How the LDAP value must match.

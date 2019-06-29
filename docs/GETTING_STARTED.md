# Getting started with Glewlwyd 2.0

The installation comes with a default configuration that can be updated or overwritten via the administration page.

The default configuration uses Glewlwyd's database as backend for users and clients. The retype-password scheme is instanciated for a session duration of 10 minutes, it's used to authenticate `g_admin` and `g_profile` scopes (for admin page and profile page). The other authentication schemes are available but must be instanciated and configured.

The following plugins are available but must be instanciated and configured either:

- Glewlwyd Oauth2 plugin

## Installation

Install Glewlwyd via the packages, CMake or Makefile. See the [installation documentation](INSTALL.md) for more details.

## First connection to the administration page

Open the administration page in your browser. The default url is [http://localhost:4953/](http://localhost:4953/). Use the default login `admin` with the default password `password`.

Make sure to change the default password for the `admin` user to a more secure password.

### User backend modules

Go to `parameters/user` menu in the navigation tab. Click on the `+` button to add a new user backend instance. The user backend modules available are:

- Database
- LDAP
- HTTP authentication

You can add the same instance of the same user backend module as many times as you want. A user backend module is distinguished by its module name and its instance name, example `database/localDB`, `ldap/companyAD`. The instance name must be unique though, i.e. you can't have `database/local` and `ldap/local` as user backend instances.

#### Database backend

The database backend requires an access to a database. You can use the same backend as the Glewlwyd server or use a different database. If you use a different database, it must be initialized with the script available in `docs/database/user/database.[sqlite3|mariadb|postgresql].sql`.

#### LDAP backend

TODO

#### HTTP authentication

With this user backend module, every time a user/password access is required, Glewlwyd will use the login/password provided to authenticate to the HTTP service configured and return the result: user valid, user invalid or server error. You must set at least one scope that will be available for all users connecting via this backend.

This module is read-only, and no user data will be stored in Glewlwyd's storage system, except the user sessions. Which means getting the user list of an HTTP backend will always return an empty list and getting the details of any username will return a build-up JSON object with the following data:

```javascript
// Response example for the username `user1`:
{
  "username": "user1",
  "scope": ["g_profile","scope1"],
  "enabled": true
}
```

### Client backend module

Go to `parameters/client` menu in the navigation tab. Click on the `+` button to add a new client backend instance. The client backend modules available are:

- Database
- LDAP

You can add the same instance of the same client backend module as many times as you want. A client backend module is distinguished by its module name and its instance name, example `database/localDB`, `ldap/companyAD`.

#### Database backend

The database backend requires an access to a database. You can use the same backend as the Glewlwyd server or use a different database. If you use a different database, it must be initialized with the script available in `docs/database/client/database.[sqlite3|mariadb|postgresql].sql`.

#### LDAP backend

TODO

### Authentication schemes

Go to `parameters/schemes` menu in the navigation tab. Click on the `+` button to add a new scheme instance. The scheme modules available are:

- E-mail code scheme
- Webauthn scheme
- HOTP/TOTP scheme
- Retype-password password scheme

You can add instances of the same scheme as many times as you want, if you need different configurations or to access different scopes in different contexts. A scheme instance is distinguished by its module name and its instance name, example `webauthn/AdminWebauthn`, `webauthn/UserWebauthn`.

#### E-mail code scheme

The requirements to use this scheme is a smtp server available, able to relay codes sent via `SMTP`.

#### Webauthn scheme

It's highly recommended to download the [google root r2 certificate](#path_2_certificate) to fully authenticate `android-safetynet` devices (Android phones or tablets version 7.0 Nougat or above).

#### HOTP/TOTP scheme

Easy-peasy

### Plugins

Go to `parameters/plugins` menu in the navigation tab. Click on the `+` button to add a new user backend instance. The plugins available are:

- Glewlwyd Oauth2 plugin

#### Glewlwyd Oauth2 plugin

This module has the same behaviour as the legacy Glewlwyd 1.x Oauth2. The new features available are:

- Allow to use a refresh token as a `"rolling refresh"`, so every time an access token is refreshed, the lifetime of the refresh token will be reset to the original duration. So if a token is refreshed periodically, users won't have to reconnect and request a new refresh token every 2 weeks or so.
- Allow to overwrite default `rolling refresh` setting and refresh token duration for every scope individually. `rolling refresh` disabled and the lowest refresh token duration have precedence in case of conflicting scopes settings.

When you create a Glewlwyd Oauth2 plugin instance, you must specify its name, its algorithm and signature size.

When the plugin instance is enabled, its endpoints available are:

- `/api/<instance_name>/auth`
- `/api/<instance_name>/token`
- `/api/<instance_name>/profile`

### Configure environment to use Glewlwyd Oauth2

You need a resource service that requires glewlwyd access tokens to work. Some applications are available in my github repositories, like [Taliesin](https://github.com/babelouest/taliesin), an audio streaming server, [Hutch](https://github.com/babelouest/hutch), a password and secret locker, or [Angharad](https://github.com/babelouest/angharad), a house automation server.

You need to add a client, at least one scope, and setup the scope(s) for a user.

#### Create the client

Click on the `+` button on the client list page in Glewlwyd admin app. You must at least set a client_id, a redirect URI and the authorization types required.

#### Configure scopes

Go to `Scopes` menu in the navigation tab. Click on the `+` button to add a new Scope.

By default, a scope requires only the password for authentication. You can specify additional authentication schemes and/or unset password authentication. You can gather authentication schemes in groups to allow multiple authentication factor, and you can have multiple groups to force more than one additional authentication factor.

The authentication group model can be represented as the following schema:

Scope 1: password `AND` (mail `OR` webauthn) `AND` (TOTP `OR` certificate)

Scope 2: (mail `OR` certificate `OR` webauthn)

#### Setup the required scopes for a user

Go to `Users` menu in the navigation tab, Click on the `Edit` button for an existing user or click on the `+` button to add a new user. Then, set the previously created scope to this user.

When the user will connect to the client with Glewlwyd, he will need to validate the authentication schemes for the scopes required with this client.

### Use case: Configure Glewlwyd to authenticate with Taliesin

This use case is based on the following assertions:
- Glewlwyd is freshly installed with default configuration
- Glewlwyd is installed on the local machine and available at the address [http://localhost:4953/](http://localhost:4953/)
- Taliesin is installed on the local machine and available at the address [http://localhost:8576/](http://localhost:8576/)
- The scope `taliesin` will be configured as a rolling refresh, with password only
- The scope `taliesin_admin` will be configured as standard refresh token, without rolling refresh enabled, with password and OTP 2nd factor or Webauthn enabled
- The tokens are jwt signed with a RSA 256 key, the key file and the certificate must be available.

To create a RSA key/certificate pair, run the following commands on a linux shell with openssl installed:

```shell
$ # private key
$ openssl genrsa -out private-rsa.key 4096
$ # public key
$ openssl rsa -in private-rsa.key -outform PEM -pubout -out public-rsa.pem
```

Open the Glewlwyd admin page [http://localhost:4953/](http://localhost:4953/) in your browser, connect as administrator (admin/password)

#### Step 1: Change admin password

Click on the `Change password` menu on the navigation tab, there, you should change the `admin` password with a more efficient password.

#### Step 2: Add OTP and Webauthn schemes

Go to `parameters/schemes` menu in the navigation tab. Click on the `+` button to add a new scheme instance.

In the new scheme modal, enter in the name field `otp`, in the display name field `OTP`, select `HOTP/TOTP` in the type dropdown. Leave the other default parameters as is and click save. The scheme OTP should appear in the scheme list.

Then click again on the `+` button to add the Webauthn scheme. In the new scheme modal, enter in the field name `webauthn`, in the display name field `Webauthn`, select `Webauthn` in the type dropdown. Leave the other default parameters as is and click save. The scheme OTP should appear in the scheme list.

#### Step 3: Add scopes in Glewlwyd

- Add the scope `taliesin`, check the password checkbox
- Add the scope `taliesin_admin`, check the password checkbox and add the schemes `OTP` and `Webauthn` to the scope

#### Step 4: Add a Glewlwyd OAuth2 plugin instance

Go to `parameters/plugins` menu in the navigation tab. Click on the `+` button to add a new plugin instance.

In the new plugin modal, enter in the name field `glwd`, in the display name field `Glewlwyd OAuth2`, select `Glewlwyd OAuth2` in the type dropdown. There, select `RSA` as JWT type, 256 as key size, set your private and public key. Deploy `Specific scope parameters` and add the scope `taliesin_admin`, uncheck `rolling refresh` for this scope.

Click `Ok`.

#### Step 5: Add the client Taliesin

Go to `Clients` menu in the navigation tab. Click on the `+` button to add a new client.

In the new client modal, enter `taliesin` in the client ID field, `Taliesin` in the name field. Add the redirect uri `http://localhost:8576/`, add the following authorization types: `code`, `token` and `refresh_token`.

#### Step 6: Add a simple user and setup admin user

Go to `Users` menu in the navigation tab. Click on the `+` button to add a new user.

In the new user modal, enter `t_user` in the username field, `Taliesin User` in the name field, set a password (8 characters minimum), add the scopes `g_profile` and `taliesin`. Click `Ok`. The new user `t_user` should appear in the users list.

#### Step 7: configure OTP and Webauthn for admin

Click on the `delegate profile` button for the user `admin`. In the new page, select `otp` in the navigation bar.

Create a new OTP scheme for the user `admin`, select `TOTP` in the dropdown list, click on the `Generate` button to generate a random secret for this scheme, click `Save`. Your TOTP scheme is configured. Then you can reproduce this configuration on another device, like an OTP application on a smartphone. You can use the generated QR Code in the profile page.

Register a new Webauthn device. Select `Webauthn` in the navigation bar.

Two types of Webauthn devices are currently supported: `fido-u2f` types like Yubikeys and `android-safetynet` types like Android phones or tablet, version 7 or above. Click on the button `Register` to add a new registration. Follow the steps on your browser to complete the registration. You can test the authentification by clicking on the `Test` button.

#### Step 8: configure Taliesin's `config.json` file

Open the file `webapp/config.json` on an editor. The file should look like this now:

```json
{
	"taliesinApiUrl": "http://localhost:8576/api",
	"storageType": "local", 
	"useWebsocket": true,
	"oauth2Config": {
		"enabled": true,
		"storageType": "local", 
		"responseType": "code", 
		"serverUrl": "http://localhost:4593/api/glwd", 
		"authUrl": "auth", 
		"tokenUrl": "token", 
		"clientId": "taliesin", 
		"redirectUri": "http://localhost:8576/", 
		"scope": "taliesin taliesin_admin",
		"profileUrl": "profile"
	}
}
```

#### Step 9: Open taliesin in your browser

Open the url [http://localhost:8576/](http://localhost:8576/) in your browser.

Click on the login button, you should be redirected to Glewlwyd's login page.

There, log in with your admin password. After that, use the second factor authenticaiton of your choice. When completed, click on the `Continue` button which should be enabled. You will be redirected to Taliesin with a valid login and able to use the application as administrator, enjoy!

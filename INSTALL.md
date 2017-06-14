# Installation

## From docker

[Rafael](https://github.com/rafaelhdr/) is currently working on a [docker image](https://github.com/rafaelhdr/glewlwyd-oauth2-server) for Glewlwyd, Kudos to him! This is a work-in-progress but you already can easily build an image with MariaDB or SQLite3 backend. Check out the documentation for more informations.

## From Github

You must install the following libraries including their header files:

```
libmicrohttpd
libjansson
libcurl 
uuid 
libldap2 
libmysqlclient 
libsqlite3 
libconfig 
libgnutls
libssl
```

On a Debian based distribution (Debian, Ubuntu, Raspbian, etc.), you can install those dependencies using the following command:

```shell
$ sudo apt-get install libmicrohttpd-dev libjansson-dev libcurl4-gnutls-dev uuid-dev libldap2-dev libmysqlclient-dev libsqlite3-dev libconfig-dev libgnutls28-dev libssl-dev
```

### Libssl vs libgnutls

Both libraries are mentionned required, but you can get rid of libssl if you install `libjwt` with the option `--without-openssl`, but `gnutls` 3.5.8 minimum is required. For this documentation to be compatible with most linux distributions (at least the one I use), I don't remove libssl from the required libraries yet.

### Debian Jessie libmicrohttpd bug

I've noticed that on a Debian Jessie and previous versions, libmicrohttpd has a bug when it parses `application/x-www-form-urlencoded` parameters. This is fixed in later version, so I suggest using the latest stable version of [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/).

Then, download Glewlwyd and its dependendencies hosted in github, compile and install.

```shell
# Install libjwt
# libtool and autoconf may be required, install them with 'sudo apt-get install libtool autoconf'
$ git clone https://github.com/benmcollins/libjwt.git
$ cd libjwt/
$ autoreconf -i
$ ./configure # use ./configure --without-openssl to use gnutls instead, you must have gnutls 3.5.8 minimum
$ make
$ sudo make install

# Install Orcania
$ git clone https://github.com/babelouest/orcania.git
$ cd orcania/
$ make
$ sudo make install

# Install Yder
$ git clone https://github.com/babelouest/yder.git
$ cd yder/src/
$ make
$ sudo make install

# Install Ulfius
$ git clone https://github.com/babelouest/ulfius.git
$ cd ulfius/src/
$ make
$ sudo make install

# Install Hoel
$ git clone https://github.com/babelouest/hoel.git
$ cd hoel/src/
$ make
$ sudo make install

# Install Glewlwyd
$ git clone https://github.com/babelouest/glewlwyd.git
$ cd glewlwyd/src/
$ make 
$ sudo make install
```

## Configuration

Copy `glewlwyd.conf.sample` to `glewlwyd.conf`, edit the file `glewlwyd.conf` with your own settings.

### login and grant urls

Update the entries `login_url` and `grant_url` in the configuration file to fit your installation, for example:

```
login_url="http://localhost:4593/app/login.html?"
grant_url="http://localhost:4593/app/grant.html?"
```

### Digest algorithm

Specify in the config file the parameter `hash_algorithm` to store passwords with sqlite3 backend, and token digests.

Algorithms available are SHA1, SHA256, SHA512, MD5.

### Data storage backend initialisation

You can use a MySql/MariaDB database or a SQLite3 database file.
Use the dedicated script, `glewlwyd.mariadb.sql` or `glewlwyd.sqlite3.sql` to initialize your database.

#### Admin scope value

If you want to use a different name for admin scope (default is `g_admin`), you must update the init script before running it, change the last line which reads:

```sql
INSERT INTO g_scope (gs_name, gs_description) VALUES ('g_admin', 'Glewlwyd admin scope');
```

With your own `gs_name` value.

#### MySql/MariaDB database initialization

Use the script `glewlwyd.mariadb.sql` provided to initialize the MySql/MariaDB database table. The example below creates a database called `glewlwyd` with user/password glewlwyd/glewlwyd.

```shell
$ mysql
mysql> CREATE DATABASE `glewlwyd`;
mysql> GRANT ALL PRIVILEGES ON glewlwyd.* TO 'glewlwyd'@'%' identified BY 'glewlwyd';
mysql> FLUSH PRIVILEGES;
mysql> USE glewlwyd
mysql> SOURCE glewlwyd.mariadb.sql
```

#### SQLite3 database file

Use the script `glewlwyd.sqlite3.sql` to initialize the SQLite3 database tables.
```shell
$ sqlite3 /var/cache/glewlwyd/glewlwyd.db < glewlwyd.sqlite3.sql
```

#### Register management webapp

To be able to connect to the front-end application, you must register it first with the script `webapp/init.sql`. For example, run this command for the MySql/Mariadb database:

```shell
$ mysql glewlwyd < webapp/init.sql
```

For the sqlite3 database backend, use the following command:

```shell
$ sqlite3 /var/cache/glewlwyd/glewlwyd.db < webapp/init.sql
```

### Authentication backend configuration

For the authentication backend, you can use a LDAP server or your database, or both. If you use both backends, then on an authentication process, the user or the client will be tested in the LDAP first, then in the database if not found.

### Add an administrator user before first use

An administrator must be present in the backend to use the application (manage scopes, users, clients, resources, authorization types).

An administrator in the LDAP backend is a user who has the `admin_scope` (default `g_admin`) in its scope list.

The following examples will add an admin with the login `admin` and the password `password`.

#### LDAP Backend administrator

Scope list is stored in the parameter `scope_property_user_read` (`o` by default).

#### Database Backend administrator (MySql/MariaDB)

To add an administrator in the MySql/MariaDB database, connect to the databse and use the following command (update with your own e-mail and password values):

```sql
$ mysql
mysql> INSERT INTO g_user (gu_login, gu_name, gu_email, gu_password, gu_enabled) VALUES ('admin', 'The Boss', 'boss@glewlwyd.domain', PASSWORD('password'), 1);
mysql> INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='admin'), (SELECT gs_id from g_scope WHERE gs_name='g_admin'));
mysql> INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='admin'), (SELECT gs_id from g_scope WHERE gs_name='g_profile'));
```

#### Database Backend administrator (SQLite3)

Since SQLite3 uses the `hash_algorithm` value to store its password, you must store the password with the correct hashed value. Use the following list for the initial password (don't forget the prefix):

```
value 'password' hashed using different algorithms:
- MD5:    {MD5}X03MO1qnZdYdgyfeuILPmQ==
- SHA1:   {SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=
- SHA256: {SHA256}XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=
- SHA512: {SHA512}sQnzu7wkTrgkQZF+0G1hi5AI3Qmzvv0bXgc5THBqi7mAsdd4Xll27ASbRt9fEyavWi6m0QP9B8lThf+rDKy8hg==
```

To add an administrator in the SQLite3 database, connect to the databse and use the following command (update with your own e-mail and password values):

```sql
$ sqlite <path_to_sqlite3_database>
sqlite> INSERT INTO g_user (gu_login, gu_name, gu_email, gu_password, gu_enabled) VALUES ('admin', 'The Boss', 'boss@glewlwyd.domain', '{MD5}X03MO1qnZdYdgyfeuILPmQ==', 1);
sqlite> INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='admin'), (SELECT gs_id from g_scope WHERE gs_name='g_admin'));
sqlite> INSERT INTO g_user_scope (gu_id, gs_id) VALUES ((SELECT gu_id from g_user WHERE gu_login='admin'), (SELECT gs_id from g_scope WHERE gs_name='g_profile'));
```

### JWT configuration

You can choose between SHA (HS512) and RSA (RS512) anglorithms to sign the tokens. Note that if you use SHA, you will need to share the `sha_secret` value with the resource providers and keep it safe in all places. If you use RSA algorithm, you will need to share the public key `rsa_pub_file` with resource providers, and you will need to keep the private key `rsa_key_file` safe.

#### RSA private/public key creation

You can use the following command to create a pair of private and public keys for the RSA algorithm:

```SHELL
$ openssl genrsa -out private.key 4096
$ openssl rsa -in private.key -outform PEM -pubout -out public.pem
```

For more information about generating RSA keys, see [OpenSSL Documentation](https://www.openssl.org/docs/)

### Install service

The files `glewlwyd-init` (SysV init) and `glewlwyd.service` (Systemd) can be used to have glewlwyd as a daemon. They are fitted for a Raspbian distrbution, but can easily be changed for other systems.

#### Install as a SysV init daemon and run

```shell
$ sudo cp glewlwyd-init /etc/init.d/glewlwyd
$ sudo update-rc.d glewlwyd defaults
$ sudo service glewlwyd start
```

#### Install as a Systemd daemon and run

```shell
$ sudo cp glewlwyd.service /etc/systemd/system
$ sudo systemctl enable glewlwyd
$ sudo sudo systemctl start glewlwyd
```

## Run Glewlwyd

Run the application using the service command if you installed the init file:

```shell
$ sudo service glewlwyd start
```

You can also manually start the application like this:

```shell
$ ./glewlwyd --config-file=glewlwyd.conf
```

By default, Glewlwyd is available on TCP port 4593. You can use the test page `tests/test-token.html` to validate the behaviour. To access it, copy the file into webapp and go to the url: [http://localhost:4593/app/test-token.html](http://localhost:4593/app/test-token.html).

## SSL/TLS

OAuth 2 specifies that a secured connection is mandatory, via SSL or TLS, to avoid data and token to be stolen, or Man-In-The-Middle attacks. Glewlwyd supports starting a secure connection with a private/public key certificate, but it also can be with a classic non-secure HTTP connection, and be available to users behind a HTTPS proxy.

## Resource server authorization usage and access tokens

Glewlwyd provides [JSON Web Tokens](https://jwt.io/) which is a standard way to validate a token without asking the authorization server.
A JSON Web Token (JWT) comes with a signature that authenticates itself.

There is no way for a resource server to determine if a token is valid, except by checking the Authorization token. i.e., there is no API where you could ask Glewlwyd server if an access token is valid or not. Therefore, the resource server MUST verify the access token using its signature.

Examples of resource server access token validation are available in the folder [clients](https://github.com/babelouest/glewlwyd/tree/master/clients/).

There are 2 ways to sign a token:
- SHA symetric encryption
- RSA asymetric encryption

The token parameters are located in the `jwt` block in the configuration file:
```
jwt =
{
   use_rsa = true
   rsa_key_file = "/usr/local/etc/glewlwyd/private.key"
   rsa_pub_file = "/usr/local/etc/glewlwyd/public.pem"

   use_sha = false
   sha_secret = "secret"

}
```

Depending on the algorithm you choose, you will need to share information with the resource services.
- With RSA encryption, the resource service will have to authenticate the tokens using the `rsa_pub_file` file content, you will have to keep secret the `rsa_key_file` file content to prevent token forgery.
- With SHA encryption, the resource service will have to authenticate the tokens using the `sha_secret` value, you must share the `sha_secret` value between the authentication server and the resource services, and keep it private between them to prevent token forgery.

In your resource server, you must validate all API call with the token given in the `Authorization` header as described in [RFC6750](https://tools.ietf.org/html/rfc6750). You can use a jwt library available for the language and architecture of your choice, to validate the token signature and content. If the token signature is verified, you MUST manually validate the token time validity using the values `iat` and `expires_in` in the token payload.

Every `access_token` has the following header and payload format:

```javascript
// Header
{
  "typ": "JWT",
  "alg": "RS512" // for RSA signatures, HS512 for SHA signatures
}
// Payload
{
  "expires_in": 3600,       // Token expiration in seconds, default is 1 hour
  "iat": 1484278795,        // Issued at, time in UNIX epoch format
  "salt": "abcd1234",       // A random string
  "scope": "scope1 scope2", // The scope values
  "type": "access_token",   // The token type
  "username": "admin"       // The username who was granted access for this scope
}
```

Refresh and session tokens are also JWTs, but their payload have slightly different values. A session token doesn't have a scope value, and the `type` values are respectively `refresh_token` and `session_token`. Although these tokens are validated by the Glewlwyd server directly.

## Front-end application

All front-end pages have a minimal design, feel free to modify them for your own need, or create your own application.

### Glewlwyd manager

Glewlwyd comes with a small front-end that uses the backend API to manage profile, users, clients, scopes, resources and authorization types.

#### Configuration

The config file `glewlwyd.conf` contains the following variables: `static_files_path` and `static_files_prefix`, `static_files_path` is the path to the front-end application. Set it to the location of your webapp folder before running glewlwyd, e.g. `"/home/pi/glewlwyd/webapp"`, `static_files_prefix` will be the url path to access to the front-end application, default is [http://localhost:4953/app/](http://localhost:4953/app/).

To connect to the management application, you must use a user that have `g_admin` scope.

The front-end management application is a tiny single page app (SPA) written in ReactJS/JQuery, responsive as much as I can, not the best design in the world, but useful anyway.

### tests/test-token.html

This page is here only for oauth2 tests and behaviour validation. If you want to use it, you need to update the `glewlwyd_api` value and all parameters provided, such as `redirect_uri`, `scope` and `client`.

Beware, all password inputs are of type `text`, so a typed password is not hidden from a hidden third-party dangerous predator.

# Installation

## Debian-ish packages

[![Packaging status](https://repology.org/badge/vertical-allrepos/glewlwyd.svg)](https://repology.org/metapackage/glewlwyd)

Glewlwyd is now available in Debian Buster (testing) and some Debian based distributions. To install it on your device, use the following command as root:

```shell
# apt install glewlwyd
```

Then, you must initialize your database, setup your jwt key and setup your `glewlwyd.conf` file

### Pre-compiled packages

You can install Glewlwyd with a pre-compiled package available in the [release pages](https://github.com/babelouest/glewlwyd/releases/latest/). The package files `glewlwyd-full_*` contain the package libraries of `orcania`, `yder`, `ulfius` and `hoel` precompiled for `glewlwyd`, plus `glewlwyd` package. To install a pre-compiled package, you need to have installed the following libraries:

```
libmicrohttpd
libjansson
libcurl-gnutls
uuid
libldap2
libmariadbclient
libsqlite3
libconfig
libgnutls
libssl
```

For example, to install Glewlwyd with the `glewlwyd-full_1.3.2_Debian_stretch_x86_64.tar.gz` package downloaded on the `releases` page, you must execute the following commands:

```shell
$ sudo apt install -y autoconf automake make pkg-config libjansson-dev libssl-dev libcurl3 libconfig9 libcurl3-gnutls libgnutls30 libgcrypt20 libmicrohttpd12 libsqlite3-0 libmariadbclient18 libtool uuid
$ wget https://github.com/benmcollins/libjwt/archive/v1.9.tar.gz
$ tar -zxvf v1.9.tar.gz
$ cd libjwt-1.9
$ autoreconf -i
$ ./configure
$ make && sudo make install
$ wget https://github.com/babelouest/glewlwyd/releases/download/v1.3.2/glewlwyd-full_1.3.2_Debian_stretch_x86_64.tar.gz
$ tar xf hoel-dev-full_1.4.0_Debian_stretch_x86_64.tar.gz
$ sudo dpkg -i liborcania_1.2.0_Debian_stretch_x86_64.deb
$ sudo dpkg -i libyder_1.2.0_Debian_stretch_x86_64.deb
$ sudo dpkg -i libhoel_1.4.0_Debian_stretch_x86_64.deb
$ sudo dpkg -i libulfius_2.3.0_Debian_stretch_x86_64.deb
$ sudo dpkg -i glewlwyd_1.3.2_Debian_stretch_x86_64.deb
```

If there's no package available for your distribution, you can recompile it manually using `CMake` or `Makefile`.

## Docker

[Rafael](https://github.com/rafaelhdr/) has made [docker images](https://github.com/rafaelhdr/glewlwyd-oauth2-server) for Glewlwyd, Kudos to him!. Check out the documentation for more informations.

## Manual install from Github

You must install the following libraries including their header files:

```
libmicrohttpd
libjansson
libcurl-gnutls
uuid
libldap2
libmariadbclient
libsqlite3
libconfig
libgnutls
libssl
```

On a Debian based distribution (Debian, Ubuntu, Raspbian, etc.), you can install those dependencies using the following command:

```shell
$ sudo apt-get install libmicrohttpd-dev libjansson-dev libcurl4-gnutls-dev uuid-dev libldap2-dev libmariadbclient-dev libsqlite3-dev libconfig-dev libgnutls28-dev libssl-dev
```

### Libssl vs libgnutls

Both libraries are mentionned required, but you can get rid of libssl if you install `libjwt` with the option `--without-openssl`. `gnutls` 3.5.8 minimum is required. For this documentation to be compatible with most linux distributions (at least the one I use), I don't remove libssl from the required libraries yet.

### Libmicrohttpd bug on POST parameters

With Libmicrohttpd 0.9.37 and older version, there is a bug when parsing `application/x-www-form-urlencoded` parameters. This is fixed in later version, from the 0.9.38, so if your Libmicrohttd version is older than that, I suggest getting a newer version of [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/).

### Build Glewlwyd and its dependencies

#### CMake

Download and install libjwt, then download Glewlwyd from GitHub, then use the CMake script to build the application:

```shell
# Install libjwt
# libtool and autoconf may be required, install them with 'sudo apt-get install libtool autoconf'
$ git clone https://github.com/benmcollins/libjwt.git
$ cd libjwt/
$ autoreconf -i
$ ./configure # use ./configure --without-openssl to use gnutls instead, you must have gnutls 3.5.8 minimum
$ make
$ sudo make install

# Install Glewlwyd
$ git clone https://github.com/babelouest/glewlwyd.git
$ mkdir glewlwyd/build
$ cd glewlwyd/build
$ cmake ..
$ make 
$ sudo make install
```

### Good ol' Makefile

Download Glewlwyd and its dependencies hosted on github, compile and install.

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
$ make DISABLE_POSTGRESQL=1
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

#### TL;DR

For a Mariadb/Mysql database, you must create a database or use an existing one first, example:

```sql
-- Create database and user
CREATE DATABASE `glewlwyd`;
GRANT ALL PRIVILEGES ON glewlwyd.* TO 'glewlwyd'@'%' identified BY 'glewlwyd';
GRANT ALL PRIVILEGES ON glewlwyd.* TO 'glewlwyd'@'localhost' identified BY 'glewlwyd';
FLUSH PRIVILEGES;
```

Then, use the script that fit your database backend and Digest algorithm in the [database](database) folder:

- `database/init-mariadb.sql`
- `database/init-sqlite3-md5.sql`
- `database/init-sqlite3-sha.sql`
- `database/init-sqlite3-sha256.sql`
- `database/init-sqlite3-sha512.sql`

##### Secuity warning!

Those scripts create a valid database that allow to use glewlwyd but to avoid potential security issues, you must make the following changes before opening Glewlwyd API to the wild web:
- Change the admin password when you connect to the application
- Change the redirect_uri value for the client `g_admin` with an absolute redirect_uri value, e.g. `http://localhost:4593/app/`, then uncomment the corresponding line in [glewlwyd.react.js](https://github.com/babelouest/glewlwyd/blob/master/webapp/app/glewlwyd.react.js#L47) and set with your value.
- Change the values `login_url` and `grant_url` in your configuration file for absolute urls, e.g. `http://localhost:4593/app/login.html?`

#### Detailed installation

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

To be able to connect to the front-end application, you must register it first with the script `database/init.sql`. For example, run this command for the MySql/Mariadb database:

```shell
$ mysql glewlwyd < database/init.sql
```

For the sqlite3 database backend, use the following command:

```shell
$ sqlite3 /var/cache/glewlwyd/glewlwyd.db < database/init.sql
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

You can choose between SHA (HS256, HS384, HS512), RSA (RS256, RS384, RS512) and ECDSA (ES256, ES384, ES512) anglorithms to sign the tokens. Note that if you use SHA, you will need to share the `sha_secret` value with the resource providers and keep it safe in all places. If you use RSA or ECDSA algorithm, you will need to share the public key specified in `[rsa|ecdsa]_pub_file` with resource providers, and you will need to keep the private key `[rsa|ecdsa]_key_file` safe.

The values available for the parameter `key_size` are 256, 284 and 512 only. To choose your signature algorithm, set the value `true` to the parameter `use_[rsa|ecdsa|sha]` you want, and `false` to the other ones. Finally, set the additional parameter used for your algorithm:
- `*_key_file` and `*_pub_file` if you choose ECDSA or RSA signatures, with the path to the public and private signature files
- `sha_secret` if you choose SHA signatures, with the value of the secret

#### RSA private/public key creation

You can use the following example commands to create a pair of private and public keys for the algorithms RSA or ECDSA:

```SHELL
$ # RS512
$ # private key
$ openssl genrsa -out private-rsa.key 4096
$ # public key
$ openssl rsa -in private-rsa.key -outform PEM -pubout -out public-rsa.pem

$ # ES512
$ # private key
$ openssl ecparam -genkey -name secp521r1 -noout -out private-ecdsa.key
$ # public key
$ openssl ec -in private-ecdsa.key -pubout -out public-ecdsa.pem
```

For more information about generating keys, see [OpenSSL Documentation](https://www.openssl.org/docs/)

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

#### Change front-end path

If you want to change the path to the front-end application, e.g. change it from http://localhost:4953/app/ to http://localhost:4953/admin/ for example, there are 2 steps to follow.

- 1: Change the values `static_files_prefix`, `login_url` and `grant_url` in the confguration file

The value `static_files_prefix` must match your new path, e.g. `admin`, the `login_url` and `grant_url` must be changed accordingly, e.g. `"../admin/login.html?"` and `"../admin/grant.html?"`.

- 2: Change the `redirect_uri` value of the g_admin client in the database, e.g.:

```SQL
UPDATE g_redirect_uri set gru_uri='../admin/index.html' where gc_id=(SELECT gc_id from g_client WHERE gc_client_id='g_admin');
```

#### Scope

To connect to the management application, you must use a user that have `g_admin` scope.

The front-end management application is a tiny single page app (SPA) written in ReactJS/JQuery, responsive as much as I can, not the best design in the world, but useful anyway.

### tests/test-token.html

This page is here only for oauth2 tests and behaviour validation. If you want to use it, you need to update the `glewlwyd_api` value and all parameters provided, such as `redirect_uri`, `scope` and `client`.

Beware, all password inputs are of type `text`, so a typed password is not hidden from a hidden third-party dangerous predator.

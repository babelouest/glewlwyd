# Installation

1. [Distribution packages](#distribution-packages)
2. [Pre-compiled packages](#pre-compiled-packages)
3. [Docker](#docker)
4. [Manual install from Github](#manual-install-from-github)
   * [CMake](#cmake)
   * [Good ol' Makefile](#good-ol-makefile)
5. [Configuration](#configuration)
   * [SSL/TLS](#ssltls)
   * [login and grant URLs](#login-and-grant-urls)
   * [Reset password](#reset-password)
   * [Digest Algorithm](#digest-algorithm)
   * [Database back-end initialisation](#database-back-end-initialisation)
   * [Authentication back-end configuration](#authentication-back-end-configuration)
   * [JWT configuration](#jwt-configuration)
   * [JWT Access Token Payload](#jwt-access-token-payload)
     * [Additional propertyn the JWT Payload](#additional-property-in-the-jwt-payload)
   * [Install as a service](#install-as-a-service)
6. [Run Glewlwyd](#run-glewlwyd)
7. [Front-end application](#front-end-application)
   * [Login, Grant access and reset password pages](#login-grant-access-and-reset-password-pages)
   * [Glewlwyd manager](#glewlwyd-manager)
   * [Glewlwyd user profile](#glewlwyd-user-profile)
8. [Client configuration](#client-configuration)
   * [Client settings in Glewlwyd](#client-settings-in-glewlwyd)
   * [Glewlwyd endpoints for the client](#glewlwyd-endpoints-for-the-client)

### Distribution packages

[![Packaging status](https://repology.org/badge/vertical-allrepos/glewlwyd.svg)](https://repology.org/metapackage/glewlwyd)

Glewlwyd is available in multiple distributions as official package. Check out your distribution documentation to install the package automatically.

```shell
$ # Example for Debian testing
$ apt install glewlwyd
```

### Pre-compiled packages

You can install Glewlwyd with a pre-compiled package available in the [release pages](https://github.com/babelouest/glewlwyd/releases/). The package files `glewlwyd-full_*` contain the package libraries of `orcania`, `yder`, `ulfius` and `hoel` pre-compiled for `glewlwyd`, plus `glewlwyd` package. To install a pre-compiled package, you need to have installed the following libraries:

```
libmicrohttpd
libjansson
libcurl-gnutls
libldap2
libmariadbclient
libsqlite3
libconfig
libgnutls
libssl
```

For example, to install Glewlwyd with the `glewlwyd-full_2.0.0_Debian_stretch_x86_64.tar.gz` package downloaded on the `releases` page, you must execute the following commands:

```shell
$ sudo apt install -y autoconf automake make pkg-config libjansson-dev libssl-dev libcurl3 libconfig9 libcurl3-gnutls libgnutls30 libgcrypt20 libmicrohttpd12 libsqlite3-0 libmariadbclient18 libtool libsystemd-dev
$ wget https://github.com/benmcollins/libjwt/archive/v1.9.0.tar.gz
$ tar -zxvf v1.10.1.tar.gz
$ cd libjwt-1.10.1
$ autoreconf -i
$ ./configure
$ make && sudo make install
$ wget https://github.com/babelouest/glewlwyd/releases/download/v1.3.2/glewlwyd-full_2.0.0_Debian_stretch_x86_64.tar.gz
$ tar xf glewlwyd-full_2.0.0_Debian_stretch_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.0.0_Debian_stretch_x86_64.deb
$ sudo dpkg -i libyder_1.4.5_Debian_stretch_x86_64.deb
$ sudo dpkg -i libhoel_1.4.9_Debian_stretch_x86_64.deb
$ sudo dpkg -i libulfius_2.6.0_Debian_stretch_x86_64.deb
$ sudo dpkg -i glewlwyd_2.0.0_Debian_stretch_x86_64.deb
```

If there's no package available for your distribution, you can recompile it manually using `CMake` or `Makefile`.

## Docker

TBD

## Manual install from Github

You must install the following libraries including their header files:

```
libsystemd
libmicrohttpd
libjansson
libcurl-gnutl
libldap2
libmariadbclient
libsqlite3
libconfig
libgnutls
libssl
libsystemd
```

On a Debian based distribution (Debian, Ubuntu, Raspbian, etc.), you can install those dependencies using the following command:

```shell
$ sudo apt-get install libsystemd-dev libmicrohttpd-dev libjansson-dev libcurl4-gnutls-dev libldap2-dev libmariadbclient-dev libsqlite3-dev libconfig-dev libgnutls28-dev libssl-dev
```

#### Journald logs

The library libsystemd-dev is required if you want to log messages in journald service. If you don't want or can't have journald, you can compile yder library without journald support. See [Yder documentation](https://github.com/babelouest/yder).

### Libssl vs libgnutls

Both libraries are mentioned required, but you can get rid of libssl if you install `libjwt` with the option `--without-openssl`. `gnutls` 3.5.8 minimum is required. For this documentation to be compatible with most Linux distributions (at least the one I use), I don't remove libssl from the required libraries yet.

### Libmicrohttpd bug on POST parameters

With Libmicrohttpd 0.9.37 and older version, there is a bug when parsing `application/x-www-form-urlencoded` parameters. This is fixed in later version, from the 0.9.38, so if your Libmicrohttpd version is older than that, I suggest getting a newer version of [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/).

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
$ make # Or make Y_DISABLE_JOURNALD=1 to disable journald logging
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

### SSL/TLS

OAuth 2 specifies that a secured connection is mandatory, via SSL or TLS, to avoid data and token to be stolen, or Man-In-The-Middle attacks. Glewlwyd supports starting a secure connection with a private/public key certificate, but it also can be with a classic non-secure HTTP connection, and be available to users behind a HTTPS proxy for example. Glewlwyd won't check that you use it in a secure connection.

### Digest algorithm

Specify in the config file the parameter `hash_algorithm` to store passwords with sqlite3 back-end, and token digests.

Algorithms available are SHA1, SHA256, SHA512, MD5.

### Database back-end initialisation

Then, use the script that fit your database back-end and Digest algorithm in the [database](database) folder:

- `database/init.mariadb.sql`
- `database/init-sqlite3.sql`
- `database/init.postgre.sql`

Note: PostgreSQL requires the extension `pgcrypto` enabled to encrypt users and clients passwords.

For example, initialise a MariaDB database:

```shell
$ mysql
mysql> CREATE DATABASE `glewlwyd`;
mysql> GRANT ALL PRIVILEGES ON glewlwyd.* TO 'glewlwyd'@'%' identified BY 'glewlwyd';
mysql> FLUSH PRIVILEGES;
mysql> USE glewlwyd
mysql> SOURCE database/init.mariadb.sql
```

Initialise a SQLite3 database:

```shell
$ sqlite3 /var/cache/glewlwyd/glewlwyd.db < database/init.sqlite3.sql
```

#### Security warning!

Those scripts create a valid database that allow to use glewlwyd but to avoid potential security issues, you must change the admin password when you connect to the application

#### Admin scope value

If you want to use a different name for admin scope (default is `g_admin`), you must update the init script with your own `gs_name` value before running it, change the last line which reads:

```sql
INSERT INTO g_scope (gs_name, gs_description) VALUES ('g_admin', 'Glewlwyd admin scope');
```

#### Administrator user

An administrator must be present in the back-end to use the application (manage scopes, users, clients, resources, authorization types).

An administrator in the LDAP back-end is a user who has the `admin_scope` (default `g_admin`) in its scope list.

### Install as a service

The files `glewlwyd-init` (SysV init) and `glewlwyd.service` (Systemd) can be used to have glewlwyd as a daemon. They are fitted for a Raspbian distribution, but can easily be changed for other systems.

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

By default, Glewlwyd is available on TCP port 4593.

## Front-end application

All front-end pages have a minimal design, feel free to modify them for your own need, or create your own application. The source code is available in `/webapp-src` and requires nodejs and npm to build.

The built front-end files are located in the webapp/ directory.

### Login, Grant access and reset password pages

These pages are used when a user requires some access to Glewlwyd. They are simple html pages with a small JavaScript/JQuery application in it to provide the expected behavior, and vanilla bootstrap 3 for the visual part. Fell free to update them to fit your needs or to adapt the front-end to your identity.

#### Login Page

![Login Page](docs/screenshots/login.png)
![Logged In](docs/screenshots/logged in.png)

This page is used when the user needs to log-in to Glewlwyd with its login/password and/or to redirect to a client with the access to the resource.

### Glewlwyd endpoints for the client

There is no universal OAuth2 client configuration but they usually require some or all of the following data:

- Authorization endpoint: This is the endpoint where the code or the implicit token is requested, the default value for Glewlwyd is [https://glewlwyd.tld/api/auth](https://glewlwyd.tld/api/auth)
- Token endpoint: This is the endpoint where the OAuth2 token is requested by auth type code, the default value for Glewlwyd is [https://glewlwyd.tld/api/token](https://glewlwyd.tld/api/token)
- Client Id: Must match the Client Id settings you provided in Glewlwyd
- Response Type: Must match one of the allowed response type you set in Glewlwyd: `implicit` (sometimes called `token`), `code`
- Scope: One or many scopes that will be requested by the client, multiple values must be separated by a space, i.e. `scope1 scope2`
- Profile endpoint: On some clients, they require a profile endpoint that will get some of the connected user profile data, the default value for Glewlwyd is [https://glewlwyd.tld/api/profile](https://glewlwyd.tld/api/profile)

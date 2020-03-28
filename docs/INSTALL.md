# Installation

1.  [Upgrade Glewlwyid from 2.0 or 2.1 to 2.2](#upgrade-glewlwyid-from-20-or-21-to-22)
    * [Upgrade to Glewlwyd 2.2.x](#upgrade-to-glewlwyd-22x)
    * [Upgrade to Glewlwyd 2.1.x](#upgrade-to-glewlwyd-21x)
2.  [Distribution packages](#distribution-packages)
3.  [Pre-compiled packages](#pre-compiled-packages)
    * [Install Glewlwyd on Debian Buster](#install-glewlwyd-on-debian-buster)
    * [Install Glewlwyd on Raspbian Buster for Raspberry Pi](#install-glewlwyd-on-raspbian-buster-for-raspberry-pi)
    * [Install Glewlwyd on Ubuntu 18.04 LTS Bionic](#install-glewlwyd-on-ubuntu-1804-lts-bionic)
    * [Install Glewlwyd on Ubuntu 19.10 Eoan](#install-glewlwyd-on-ubuntu-1910-eoan)
4.  [Docker](#docker)
5.  [Manual install from source](#manual-install-from-source)
    * [Dependencies](#dependencies)
    * [Build Glewlwyd and its dependencies](#build-glewlwyd-and-its-dependencies)
6.  [Configure glewlwyd.conf](#configure-glewlwyd)
    * [Port number](#port-number)
    * [External URL](#external-url)
    * [SSL/TLS](#ssl-tls)
    * [Digest algorithm](#digest-algorithm)
    * [Database back-end initialisation](#database-back-end-initialisation)
    * [Static files mime types](#static-files-mime-types)
    * [Install as a service](#install-as-a-service)
7.  [Initialise database](#initialise-database)
8.  [Install as a service](#install-as-a-service)
9.  [Fail2ban filter](#fail2ban-filter)
10. [Front-end application](#front-end-application)
    * [webapp/config.json](#webappconfigjson)
    * [Internationalization](#internationalization)
    * [Login, Admin and Profile pages](#login-admin-and-profile-pages)
    * [Customize css](#customize-css)
    * [Customize titles and logos](#customize-titles-and-logos)
11. [Run Glewlwyd](#run-glewlwyd)
12. [Getting started with the application](#getting-started-with-the-application)
13. [Running Glewlwyd in test mode for integration tests](#running-glewlwyd-in-test-mode-for-integration-tests)

## Upgrade Glewlwyid from 2.0 or 2.1 to 2.2

Glewlwyd upgrades come with database changes. It is highly recommended to backup your database before performing the upgrade.

### Upgrade to Glewlwyd 2.2.x

#### Mandatory core tables upgrade

Small changes were added to the core tables. You must execute the script depending on your database backend:

- Mariadb: [upgrade-2.2-core.mariadb.sql](database/upgrade-2.2-core.mariadb.sql)

```shell
$ mysql glewlwyd < docs/database/upgrade-2.2-core.mariadb.sql
```

- SQlite3: [upgrade-2.2-core.sqlite3.sql](database/upgrade-2.2-core.sqlite3.sql)

```shell
$ sqlite3 /path/to/glewlwyd.db < docs/database/upgrade-2.2-core.sqlite3.sql
```

- PostgreSQL: [upgrade-2.2-core.postgresql.sql](database/upgrade-2.2-core.postgresql.sql)

```shell
$ psql glewlwyd < docs/database/upgrade-2.2-core.postgresql.sql
```

#### Scheme OAuth2/OIDC

In Glewlwyd 2.2, the new scheme [OAuth2/OIDC external login](OAUTH2_SCHEME.md) was introduced. To use this module, you must create its required tables by executing the script depending on your database backend:

- Mariadb: [oauth2.mariadb.sql](../src/scheme/oauth2.mariadb.sql)

```shell
$ mysql glewlwyd < src/scheme/oauth2.mariadb.sql
```

- SQlite3: [oauth2.sqlite3.sql](../src/scheme/oauth2.sqlite3.sql)

```shell
$ sqlite3 /path/to/glewlwyd.db < src/scheme/oauth2.sqlite3.sql
```

- PostgreSQL: [oauth2.postgresql.sql](../src/scheme/oauth2.postgresql.sql)

```shell
$ psql glewlwyd < src/scheme/oauth2.postgresql.sql
```


### Upgrade to Glewlwyd 2.1.x

In Glewlwyd 2.1, the plugin module [register](REGITSER.md) has appear. In order to use this module, you must add its tables by executing the script depending on your database backend:

- Mariadb: [register.mariadb.sql](../src/plugin/register.mariadb.sql)

```shell
$ mysql glewlwyd < src/plugin/register.mariadb.sql
```

- SQlite3: [register.sqlite3.sql](../src/plugin/register.sqlite3.sql)

```shell
$ sqlite3 /path/to/glewlwyd.db < src/plugin/register.sqlite3.sql
```

- PostgreSQL: [register.postgresql.sql](../src/plugin/register.postgresql.sql)

```shell
$ psql glewlwyd < src/plugin/register.postgresql.sql
```


## Distribution packages

[![Packaging status](https://repology.org/badge/vertical-allrepos/glewlwyd.svg)](https://repology.org/metapackage/glewlwyd)

Glewlwyd is available in some distributions as official package. Check out your distribution documentation to install the package automatically.

```shell
$ # Example to install Glewlwyd 1.4.9 on Ubuntu 19.10
$ apt install glewlwyd
```

## Pre-compiled packages

You can install Glewlwyd with a pre-compiled package available in the [release pages](https://github.com/babelouest/glewlwyd/releases/). The package files `glewlwyd-full_*` contain the package libraries of `orcania`, `yder`, `ulfius`, `hoel` pre-compiled for `glewlwyd`, plus `glewlwyd` package. To install a pre-compiled package, you need the following libraries installed:

```
libmicrohttpd
libjansson
libcurl
libldap2
libmariadbclient
libsqlite3
libpq
libconfig
libgnutls
libjwt
liboath
libcbor
```

### Install Glewlwyd on Debian Buster

```shell
$ sudo apt install -y libjansson4 libjwt0 libcbor0 libsqlite3-0 default-mysql-client libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.2.0/glewlwyd-full_2.2.0_debian_buster_x86_64.tar.gz
$ tar xf glewlwyd-full_2.2.0_debian_buster_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.1.0_debian_buster_x86_64.deb
$ sudo dpkg -i libyder_1.4.10_debian_buster_x86_64.deb
$ sudo dpkg -i libhoel_1.4.14_debian_buster_x86_64.deb
$ sudo dpkg -i libulfius_2.6.5_debian_buster_x86_64.deb
$ sudo dpkg -i librhonabwy_0.9.5_debian_buster_x86_64.deb
$ sudo dpkg -i libiddawc_0.9.4_debian_buster_x86_64.deb
$ sudo dpkg -i glewlwyd_2.2.0_debian_buster_x86_64.deb
```

### Install Glewlwyd on Raspbian Buster for Raspberry Pi

```shell
$ sudo apt install -y libjansson4 libjwt0 libcbor0 libsqlite3-0 default-mysql-client libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.2.0/glewlwyd-full_2.2.0_raspbian_buster_armv6l.tar.gz
$ tar xf glewlwyd-full_2.2.0_raspbian_buster_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.0.0_raspbian_buster_x86_64.deb
$ sudo dpkg -i libyder_1.4.6_raspbian_buster_x86_64.deb
$ sudo dpkg -i libhoel_1.4.14_raspbian_buster_x86_64.deb
$ sudo dpkg -i libulfius_2.6.1_raspbian_buster_x86_64.deb
$ sudo dpkg -i librhonabwy_0.9.5_raspbian_buster_x86_64.deb
$ sudo dpkg -i libiddawc_0.9.4_raspbian_buster_x86_64.deb
$ sudo dpkg -i glewlwyd_2.2.0_raspbian_buster_x86_64.deb
```

### Install Glewlwyd on Ubuntu 18.04 LTS Bionic

```shell
$ # Note: jansson and libjwt provided in Ubuntu 18.04 LTS Bionic are too old to work with Glewlwyd, here is the procedure to install them from the source
$ # If you have installed their packages, please uninstall them first
$ sudo apt remove libjwt0 libjansson4
$ sudo apt install -y pkg-config autoconf automake make cmake libtool libsqlite3-0 libmariadbclient18 libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0 libcbor0 libssl-dev libmicrohttpd12 default-mysql-client wget
$ wget https://github.com/benmcollins/libjwt/archive/v1.12.0.tar.gz -O libjwt.tar.gz
$ tar -zxvf libjwt.tar.gz
$ cd libjwt-1.12.0
$ autoreconf -i
$ ./configure
$ make && sudo make install
$ cd ..
$ wget https://github.com/akheron/jansson/archive/v2.12.tar.gz -O jansson.tar.gz
$ tar xf jansson.tar.gz
$ cd jansson-2.12
$ autoreconf -i
$ ./configure
$ make
$ sudo make install
$ cd ..
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.2.0/glewlwyd-full_2.2.0_ubuntu_bionic_x86_64.tar.gz
$ tar xf glewlwyd-full_2.2.0_ubuntu_bionic_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.1.0_ubuntu_bionic_x86_64.deb
$ sudo dpkg -i libyder_1.4.10_ubuntu_bionic_x86_64.deb
$ sudo dpkg -i libhoel_1.4.14_ubuntu_bionic_x86_64.deb
$ sudo dpkg -i libulfius_2.6.5_ubuntu_bionic_x86_64.deb
$ sudo dpkg -i librhonabwy_0.9.5_ubuntu_bionic_x86_64.deb
$ sudo dpkg -i libiddawc_0.9.4_ubuntu_bionic_x86_64.deb
$ sudo dpkg -i glewlwyd_2.2.0_ubuntu_bionic_x86_64.deb
```

### Install Glewlwyd on Ubuntu 19.10 Eoan

```shell
$ sudo apt install -y libjansson4 libjwt0 libcbor0 libsqlite3-0 default-mysql-client libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.2.0/glewlwyd-full_2.2.0_ubuntu_eoan_x86_64.tar.gz
$ tar xf glewlwyd-full_2.2.0_ubuntu_eoan_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.1.0_ubuntu_eoan_x86_64.deb
$ sudo dpkg -i libyder_1.4.10_ubuntu_eoan_x86_64.deb
$ sudo dpkg -i libhoel_1.4.14_ubuntu_eoan_x86_64.deb
$ sudo dpkg -i libulfius_2.6.5_ubuntu_eoan_x86_64.deb
$ sudo dpkg -i librhonabwy_0.9.5_ubuntu_eoan_x86_64.deb
$ sudo dpkg -i libiddawc_0.9.4_ubuntu_eoan_x86_64.deb
$ sudo dpkg -i glewlwyd_2.2.0_ubuntu_eoan_x86_64.deb
```

If there's no package available for your distribution, you can compile it manually using `CMake` or `Makefile`.

## Docker

The docker page is available at the following address: [https://hub.docker.com/r/babelouest/glewlwyd](https://hub.docker.com/r/babelouest/glewlwyd)

### Quickstart for tests only

Run the official docker image `babelouest/glewlwyd` hosted on docker cloud, example:

```shell
docker run --rm -it -p 4593:4593 babelouest/glewlwyd
```

- User: `admin`
- Password : `password`

This image configuration uses a sqlite3 database hosted inside the docker instance, so all data will be lost when the docker instance will be stopped. Also, this docker instance can be accessible vie the address [http://localhost:4593/](http://localhost:4593).

In this instance, both configuration files `glewlwyd.conf` (backend) and `config.json` (frontend) are stored in `/etc/glewlwyd`.

If you need to make the docker instance available in a network, you must update the configuration files as explained below by updating at least the configuration variable `external_url`.

**Customize configuration files without rebuilding the docker image**

You can overwrite the configuration files `glewlwyd.conf` and `config.json` by mounting a volume on `/etc/glewlwyd` when you run the docker image. Point this volume to a local directory on the host.

You can use the files [docker/config/glewlwyd.conf](docker/config/glewlwyd.conf) and [docker/config/config.json](docker/config/config.json) as a starting point to build your config files for docker.

```shell
$ docker run --rm -it -p 4593:4593 -v /path/to/your/config:/etc/glewlwyd babelouest/glewlwyd
```

### Docker image builder

The root directory contains a Docker file to build the docker image from the source. To build your own docker image, go to Glewlwyd source root directory and run `make docker`. This will build a docker image called `babelouest/glewlwyd:src`.

```shell
$ make docker
$ docker run --rm -it -p 4593:4593 -v /path/to/your/config:/etc/glewlwyd babelouest/glewlwyd:src
```

You can use the same options and configuration than in the official docker image, including customized configuration files.

## Manual install from source

Glewlwyd has been successfuly compiled for the folowing distribtions:

- Fedora 29+
- OpenSuse Leap 15
- OpenSuse Tumbleweed

And probably more!

Let me know if Glewlwyd can be installed and working on your distribution by opening an [issue](https://github.com/babelouest/glewlwyd/issues), if needed, you can describe the non-documented commands required for your case.

Download the [latest source tarball](https://github.com/babelouest/glewlwyd/releases/latest) or [git clone](https://github.com/babelouest/glewlwyd.git) from master branch in GitHub.

### Dependencies

On a Debian based distribution (Debian, Ubuntu, Raspbian, etc.), you can install those dependencies using the following command:

```shell
$ sudo apt-get install libmicrohttpd-dev sqlite3 libsqlite3-dev default-libmysqlclient-dev libpq-dev libgnutls-dev libconfig-dev libldap2-dev liboath-dev libjwt-dev libcbor-dev
```

#### Libmicrohttpd 0.9.38 minimum required

With Libmicrohttpd 0.9.37 and older version, there is a bug when parsing `application/x-www-form-urlencoded` parameters. This is fixed in later version, from the 0.9.38, so if your Libmicrohttpd version is older than that, I suggest getting a newer version of [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/).

#### Libmicrohttpd 0.9.70 minimum recommended in some edge cases

A bug has been [fixed](https://git.gnunet.org/libmicrohttpd.git/tree/ChangeLog?h=v0.9.70#n9) in Libmicrohttpd 0.9.70 that fixed a bug that appeared at least with [Jenkins OIDC plugin](https://wiki.jenkins.io/display/JENKINS/Openid+Connect+Authentication+Plugin) (see issue #89). It is recommended to install Libmicrohttpd 0.9.70 minimum to avoid this problems.

### Build Glewlwyd and its dependencies

#### CMake

Download and install libjwt, then download Glewlwyd from GitHub, then use the CMake script to build the application. CMake will automatically download and build Ulfius, Hoel, Yder and Orcania if they are not present on the system.

```shell
# Install Glewlwyd
$ git clone https://github.com/babelouest/glewlwyd.git
$ mkdir glewlwyd/build
$ cd glewlwyd/build
$ cmake ..
$ make 
$ sudo make install
```

The available options for cmake are:
- `-DDOWNLOAD_DEPENDENCIES=[on|off]` (default `on`): Download some dependencies if missing or using an old version: `Orcania`, `Yder`, `Ulfius` and `Hoel`
- `-DWITH_JOURNALD=[on|off]` (default `on`): Build with journald (SystemD) support
- `-DCMAKE_BUILD_TYPE=[Debug|Release]` (default `Release`): Compile with debugging symbols or not
- `-DWITH_SQLITE3=[on|off]` (default `on`): Enable/disabe SQLite3 database backend: This option is passed to Hoel library builder
- `-DWITH_MARIADB=[on|off]` (default `on`): Enable/disabe MariaDB/Mysql database backend: This option is passed to Hoel library builder
- `-DWITH_PGSQL=[on|off]` (default `on`): Enable/disabe PostgreSQL database backend: This option is passed to Hoel library builder
- `-DWITH_JOURNALD=[on|off]` (default `on`): Build with journald (SystemD) support for logging: This option is passed to Yder library builder
- `-DBUILD_GLEWLWYD_TESTING=[on|off]` (default `off`): Build testing tree
- `-DWITH_MOCK=[on|off]` (default `off`): Build mock modules, for development use only!
- `-DWITH_USER_DATABASE=[on|off]` (default `on`): Build user database backend module
- `-DWITH_USER_LDAP=[on|off]` (default `on`): Build user LDAP backend module
- `-DWITH_USER_HTTP=[on|off]` (default `on`): Build user HTTP auth backend module
- `-DWITH_CLIENT_DATABASE=[on|off]` (default `on`): Build client database backend module
- `-DWITH_CLIENT_LDAP=[on|off]` (default `on`): Build client LDAP backend module
- `-DWITH_SCHEME_RETYPE_PASSWORD=[on|off]` (default `on`): Build authentication scheme `retype password`
- `-DWITH_SCHEME_EMAIL=[on|off]` (default `on`): Build authentication scheme `e-mail code`
- `-DWITH_SCHEME_OTP=[on|off]` (default `on`): Build authentication scheme `OTP`
- `-DWITH_SCHEME_WEBAUTHN=[on|off]` (default `on`): Build authentication scheme `Webauthn`
- `-DWITH_PLUGIN_OAUTH2=[on|off]` (default `on`): Build Plugin `Glewlwyd OAuth2`
- `-DWITH_PLUGIN_OIDC=[on|off]` (default `on`): Build Plugin `OpenID Connect`

#### Good ol' Makefile

Download Glewlwyd and its dependencies hosted on GitHub, compile and install.

```shell
# Install Orcania
$ git clone https://github.com/babelouest/orcania.git
$ cd orcania/src/
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
$ make
$ sudo make install

# Install Glewlwyd
$ git clone https://github.com/babelouest/glewlwyd.git
$ cd glewlwyd/src/
$ make 
$ sudo make install
```

## Configure glewlwyd

Glewlwyd requires several configuration variables to work. You can specify those variables in a configuration file, environment variables, or both. In addition, some variables can be set via command-line arguments.

To run Glewlwyd with the config file, copy `glewlwyd.conf.sample` to `glewlwyd.conf`, edit the file `glewlwyd.conf` with your own settings.

The following paragraphs describe all the configuration parameters.

To enable environment variables in Glewlwyd, you must execute the program with the `-e` command-line argument.

You can use environment variable configuration, configuration file and command-line arguments at the same time, just keep in mind the following priority order: command-line arguments have the higher priority, followed by the environment variables, then the configuration file.

When you change the configuration file or the environment variables values, you must restart Glewlwyd to use the new configuration.

### Port number

- Config file variable: `port`
- Environment variable: `GLWD_PORT`

Optional, The TCP port the service will listen to incoming connections. The port number must be available to the user running Glewlwd process. Default value is 4593.

### Bind address

- config file variable: `bind_address`
- Environment variable: "GLWD_BIND_ADDRESS`

Optional, use this address to bind incoming connections, can be use to restrict glewlwyd service to listen to a specific network, or localhost. Must be an IPV4 address. If not set or empty, all addresses will be able to connect to Glewlwyd. Note: this is NOT a `listen` option, this setting means that Glewlyd will accept connection sent to this address only, not from it.

### External URL

- Config file variable: `external_url`
- Environment variable: `GLWD_EXTERNAL_URL`

Mandatory, exact value of the external url where this instance will be accessible to users, ex `https://glewlwyd.tld`

### API Prefix

- Config file variable: `api_prefix`
- Environment variable: `GLWD_API_PREFIX`

Optional, the url prefix where Glewlwyd's APIs will be available. Default value is `/api`.

### Login URL

- Config file variable: `login_url`
- Environment variable: `GLWD_LOGIN_URL`

Optional, name of the login page. Default value is `login.html`

### Delete profile

- Config file variable: `delete_profile`
- Environment variable: `GLWD_PROFILE_DELETE`

Optional, wether the user can remove its own account or not. Values available are:
- `no`: The user can't remove its own account
- `disable`: If the user removes its own account, the account will be disabled but not removed
- `delete`: If the user removes its own account, the account and the schemes registration will be completely removed

### Static files path

- Config file variable: `static_files_path`
- Environment variable: `GLWD_STATIC_FILES_PATH`

Optional, local path to the webapp files. If not set, the front-end application will not be available, only the APIs.

### Static files mime types

- Config file variable: `static_files_mime_types`
- Environment variable: `GLWD_STATIC_FILES_MIME_TYPES` in JSON array format, example '[{"extension":".html","mime_type":"text/html"}{"extension":".css","mime_type":"text/css"}]'

Optional, list of mime types for the webapp files.

### Allow Origin

- Config file variable: `allow_origin`
- Environment variable: `GLWD_ALLOW_ORIGIN`

### Logs

#### Log Mode:

- Config file variable: `log_mode`
- Environment variable: `GLWD_LOG_MODE`
- Command-line argument: `-m<mode>` or `--log-mode=<mode>`

### Log Level

- Config file variable: `log_level`
- Environment variable: `GLWD_LOG_LEVEL`
- Command-line argument: `-l<level>` or `--log-level=<level>`

### Log File Path

- Config file variable: `log_file`
- Environment variable: `GLWD_LOG_FILE`
- Command-line argument: `-f<file_path>` or `--log-file=<file_path>`

Optional. Default no logs.

Log modes available are `console`, `journald`, `syslog`, `file`. Multiple values must be separated by a comma, example `console,syslog`.
Log levels available are `NONE`, `ERROR`, `WARNING`, `INFO`, `DEBUG`.

If log mode `file` is set, log file path must be set to a file path where Glewlwyd process has write access.

### Cookies configuration

#### Cookie domain

- Config file variable: `cookie_domain`
- Environment variable: `GLWD_COOKIE_DOMAIN`

#### Cookie secure

- Config file variable: `cookie_secure`
- Environment variable: `GLWD_COOKIE_SECURE`

Optional. Default, cookie secure false.

The sample config file has the following cookies configuration:

```
# cookie domain
cookie_domain="localhost"

# cookie_secure, this options SHOULD be set to 1, set this to 0 to test glewlwyd on insecure connection http instead of https
cookie_secure=0
```

You must change the value `cookie_domain` accordingly to the domain name Glewlwyd will be available to. You can disable this option if you need to, but it's highly NOT recommended:

```
#cookie_domain="localhost"
```

The parameter `cookie_secure` is set to 0 by default, but since you should use Glewlwyd in a https connection, you should set this option to 1.

### Cookie Session values

#### Cookie Session expiration (in seconds)

- Config file variable: `session_expiration`
- Environment variable: `GLWD_SESSION_EXPIRATION`

#### Cookie Session key

- Config file variable: `session_key`
- Environment variable: `GLWD_SESSION_KEY`

Optional, default values are:

```
session_expiration = 2419200
session_key = GLEWLWYD2_SESSION_ID
```

### Default scope names

#### Admin scope

- Config file variable: `admin_scope`
- Environment variable: `GLWD_ADMIN_SCOPE`

#### Profile scope

- Config file variable: `profile_scope`
- Environment variable: `GLWD_PROFILE_SCOPE`

Optional, default values are:

```
admin_scope="g_admin"
profile_scope="g_profile"
```

### Modules paths

#### User modules path

- Config file variable: `user_module_path`
- Environment variable: `GLWD_USER_MODULE_PATH`

Mandatory, path to user modules.

#### Client modules path

- Config file variable: `client_module_path`
- Environment variable: `GLWD_CLIENT_MODULE_PATH`

Mandatory, path to client modules.

#### User auth scheme modules path

- Config file variable: `user_auth_scheme_module_path`
- Environment variable: `GLWD_AUTH_SCHEME_MODUE_PATH`

Mandatory, path to authentication scheme modules.

#### Plugin modules path

- Config file variable: `plugin_module_path`
- Environment variable: `GLWD_PLUGIN_MODULE_PATH`

Mandatory, path to plugin modules.

### Digest algorithm

- Config file variable: `hash_algorithm`
- Environment variable: `GLWD_HASH_ALGORITHM`

Optional, default value is `SHA256`.

Specify in the config file the parameter `hash_algorithm` to store token and secret digests.

Algorithms available are `SHA1`, `SHA256`, `SHA512` and `MD5`. Algorithms recommended are `SHA256` or `SHA512`.

### SSL/TLS

#### Use secure connection

- Config file variable: `use_secure_connection`
- Environment variable: `GLWD_USE_SECURE_CONNECTION`

#### Secure connection key file

- Config file variable: `secure_connection_key_file`
- Environment variable: `GLWD_SECURE_CONNECTION_KEY_FILE`

#### Secure connection pem file

- Config file variable: `secure_connection_pem_file`
- Environment variable: `GLWD_SECURE_CONNECTION_PEM_FILE`

#### Secure connection ca file

This configuration is mandatory only if you want to use TLS Certificate authentication schemes in direct access, it must contain the CA certificate file used to authenticate clients certificates. Otherwise you can skip it.

If this option is set, users can still connect to Glewlwyd without TLS certificate.

- Config file variable: `secure_connection_ca_file`
- Environment variable: `GLWD_SECURE_CONNECTION_CA_FILE`

OAuth 2 specifies that a secured connection is mandatory, via SSL or TLS, to avoid data and token to be stolen, or Man-In-The-Middle attacks. Glewlwyd supports starting a secure connection with a private/public key certificate, but it also can be with a classic non-secure HTTP connection, and be available to users behind a HTTPS proxy for example. Glewlwyd won't check that you use it in a secure connection, but you should.

These configuration variables are optionnal. Default is no secure connection.

### Database back-end initialisation

Configure your database backend according to the database you will use.

```
# MariaDB/Mysql configuration file variables
database =
{
  type     = "mariadb"
  host     = "localhost"
  user     = "glewlwyd"
  password = "glewlwyd"
  dbname   = "glewlwyd"
  port     = 0
}
# MariaDB/Mysql environment variables
GLWD_DATABASE_TYPE must be set to "mariadb"
GLWD_DATABASE_MARIADB_HOST
GLWD_DATABASE_MARIADB_USER
GLWD_DATABASE_MARIADB_PASSWORD
GLWD_DATABASE_MARIADB_DBNAME
GLWD_DATABASE_MARIADB_PORT

# SQLite database configuration file variables
database =
{
  type = "sqlite3"
  path = "/var/cache/glewlwyd/glewlwyd.db"
}
# SQLite database environment variables
GLWD_DATABASE_TYPE must be set to "sqlite3"
GLWD_DATABASE_SQLITE3_PATH

# PostgreSQL database configuration file variables
database =
{
  type = "postgre"
  conninfo = "host=localhost port=5432 dbname=glewlwyd user=glewlwyd password=secret"
}
# PostgreSQL database environment variables
GLWD_DATABASE_TYPE must be set to "postgre"
GLWD_DATABASE_POSTGRE_CONNINFO
```

Database configuration is mandatory.

## Initialise database

Use the script that fit your database back-end in the [database](database) folder:

- `docs/database/init.mariadb.sql`
- `docs/database/init.sqlite3.sql`
- `docs/database/init.postgre.sql`

Note: PostgreSQL requires the extension `pgcrypto` enabled to encrypt users and clients passwords.

For example, initialise a MariaDB database:

```shell
$ mysql
mysql> CREATE DATABASE `glewlwyd`;
mysql> GRANT ALL PRIVILEGES ON glewlwyd.* TO 'glewlwyd'@'%' identified BY 'glewlwyd';
mysql> FLUSH PRIVILEGES;
mysql> USE glewlwyd
mysql> SOURCE docs/database/init.mariadb.sql
```

Initialise a SQLite3 database:

```shell
$ sqlite3 /var/cache/glewlwyd/glewlwyd.db < docs/database/init.sqlite3.sql
```

Initialize a PostgreSQL database:

Check out [PostgreSQL documentation](https://www.postgresql.org/docs) and select your version for more information on the following commands.

```shell
$ psql -hlocalhost -Upostgres
postgres=# create role glewlwyd login password 'secret';
postgres=# create database glewlwyd owner glewlwyd;
postgres=# grant connect on database glewlwyd to glewlwyd;
postgres=# \c glewlwyd
glewlwyd=# create extension pgcrypto;
glewlwyd=# \c glewlwyd glewlwyd
glewlwyd=> \i docs/database/init.postgre.sql
glewlwyd=> \q
```

### Security warning!

Those scripts create a valid database that allow to use glewlwyd. But to avoid potential security issues, you must change the admin password when you first connect to the application.

### Built-in scope values

If you want to use a different name for admin scope (default is `g_admin`), or the profile scope (default is `g_profile`), you must update the init script with your own value before running it, change the lines below accordingly.

### Administrator user

An administrator must be present in the back-end to manage the application (manage scopes, users, clients, resources, authorization types).

An administrator in the LDAP back-end is a user who has the `admin_scope` (default `g_admin`) in its scope list.

## Install as a service

The files `docs/glewlwyd-init` (SysV init) and `docs/glewlwyd.service` (Systemd) can be used to run glewlwyd as a daemon. They are fitted for a Raspbian distribution, but can easily be changed for other systems. It's highly recommended to run Glewlwyd as a user without root access. Glewlwyd requires to be able to open a TCP port connection, a full access to the glewlwyd database, read access to the config file `glewlwyd.conf` and the installed `webapp/` folder (typically `/usr/share/glewlwyd/webapp`.

### Install as a SysV init daemon and run

```shell
$ sudo cp glewlwyd-init /etc/init.d/glewlwyd
$ sudo update-rc.d glewlwyd defaults
$ sudo service glewlwyd start
```

### Install as a Systemd daemon and run

```shell
$ sudo cp glewlwyd.service /etc/systemd/system
$ sudo systemctl enable glewlwyd
$ sudo systemctl start glewlwyd
```

## Fail2ban filter

You can add specific filter for fail2ban to ban potential attackers.

The `glewlwyd.conf` file is available in [fail2ban/glewlwyd.conf](fail2ban/glewlwyd.conf). It will ban the IP addresses using the following rules:
- `Authorization invalid` - on a failed auth
- `Code invalid` - on invalid code in OAuth2 or OIDC
- `Token invalid` - on invalid token refresh or token delete in OAuth2 or OIDC
- `Scheme email - code sent` - when an OTP code is sent via e-mail, to mitigate users spam

The `glewlwyd.conf` has the following content:

```config
# Fail2Ban filter for Glewlwyd
#
# Author: Nicolas Mora
#

[Definition]

failregex = ^.* - Glewlwyd WARNING: Security - Authorization invalid for username .* at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Code invalid at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Token invalid at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Scheme email - code sent for username .* at IP Address <HOST>
ignoreregex =
```

You must place the file `glewlwyd.conf` under the fail2ban `filter.d` directory (On Debian-based distrib it's located in `/etc/fail2ban/filter.d/`).

Then, you must update your `jail.local` file (On Debian-based distrib it's located in `/etc/fail2ban/jail.local`) by adding the following paragraph:

```config
[glewlwyd]
enabled  = true
filter   = glewlwyd
logpath  = /var/log/glewlwyd.log
port     = https,4593 # the TCP port where Glewlwyd is available
```

Check out [Fail2ban](https://www.fail2ban.org/) documentation for more information.

## Logrotate configuration

You can add a logrotate configuration file to help you managing Glewlwyd's logs.

Example of a `/etc/logrotate.d/glewlwyd` file. This file will create a new log file every week, compress the old files and keep 52 files (1 year):

```
/var/log/glewlwyd.log {
        rotate 52
        weekly
        compress
        copytruncate
        missingok
}
```

## Front-end application

All front-end pages have a minimal design, feel free to modify them for your own need, or create your own application. The source code is available in `/webapp-src` and requires nodejs and npm or yarn to build.

The built front-end files are located in the webapp/ directory.

### webapp/config.json

The front-end configuration file must be available under `webapp/config.json` you can copy the file `webapp/config.json.sample`.

You should update the urls of the API and the html page to match your configuration:

Example:

```Javascript
{
  "GlewlwydUrl": "https://glewlwyd.tld/",
  "ProfileUrl": "https://glewlwyd.tld/profile.html",
  "AdminUrl": "https://glewlwyd.tld/index.html",
  "LoginUrl": "https://glewlwyd.tld/login.html"
}
```

The front-end application is written in Javascript using mostly ReactJS and JQuery, ES6 minimum is required. Recent versions of browsers like Firefox, Chrom[e|ium], Edge or Safari work fine.

By choice, Glewlwyd isn't available for Internet Explorer or browser with a poor javascript engine. If you really need it you can build the front-end application with `babel-polyfill`. Check out the [webapp-src documentation](../webapp-src/README.md).

### Internationalization

The languages available in the front-end are English, French and Dutch. If you make a language file for another lang, you can add it in your Glewlwyd installation by adding the file in  `webapp/{lang}/translation.json` where `{lang}` is the translation language in ISO 639-1 format (2 letters). Then, add your new language 2-letters code in the `webapp/config.json` file in the `lang` key, example for adding korean language:

```json
"lang": ["en","fr","nl","ko"],
```

Also, feel free to send your new language file if you want to add it in the official project. The new language file must be under MIT license to be added in the project repository.

### Login, Admin and Profile pages

These pages are used when a user requires some access to Glewlwyd. They are simple html pages with a small JavaScript/JQuery/ReactJS application in it to provide the expected behavior, and vanilla bootstrap 4 for the visual consistency. Glewlwyd front-end source code is under MIT license. Fell free to update them to fit your needs or to adapt the front-end to your identity.

### Customize css

If you need to customize the css only, you can update the following files:
- [webapp/css/glewlwyd-custom.css](../webapp/css/glewlwyd-custom.css): update the css for the 3 applications (admin, login, profile)
- [webapp/css/profile-custom.css](../webapp/css/profile-custom.css) : update the css for the profile application only
- [webapp/css/admin-custom.css](../webapp/css/admin-custom.css) : update the css for the admin application only
- [webapp/css/login-custom.css](../webapp/css/login-custom.css) : update the css for the login application only

### Customize titles and logos

In all pages, the navigation bar has the Glewlwyd logo and the title `Glewlwyd`. You can change them in each pages individually.

#### Change logo

Replace the files in `webapp/img/` with your own. Each file is used in each page of the applications. Feel free to use your own organization logo or event.

- [webapp/img/logo-admin.png](../webapp/img/logo-admin.png) : Logo in the admin application
- [webapp/img/logo-login.png](../webapp/img/logo-login.png) : Logo in the login application
- [webapp/img/logo-profile.png](../webapp/img/logo-profile.png) : Logo in the profile application

#### Change navigation menu title

Change values in the internationalization files located in `webapp/locales/*/translations.json`:

Each title is identified by the key `menu-title` in each block specific to a page of the applications, you can change the value with your own title.

- Admin page:

```javascript
{
  "admin": {
    [...]
    "menu-title": "Glewlwyd",
    [...]
}
```

- Login page:

```javascript
{
  "login": {
    [...]
    "menu-title": "Glewlwyd",
    [...]
}
```

- Profile page:

```javascript
{
  "profile": {
    [...]
    "menu-title": "Glewlwyd",
    [...]
}
```

#### Change HTML page title

Change the tag content value `<title>` in the following HTML pages:

- [webapp/index.html](../webapp/index.html): Admin page
- [webapp/login.html](../webapp/login.html): Login page
- [webapp/profile.html](../webapp/profile.html): Profile page

## Run Glewlwyd

Run the application using the service command if you installed the init file:

```shell
$ sudo service glewlwyd start
```

You can also manually start the application:

```shell
$ # start Glewlwyd using a configuration file
$ glewlwyd --config-file=glewlwyd.conf
$ # start Glewlwyd using environment variables
$ GLWD_PORT=4593 GLWD_EXTERNAL_URL=http://localhost:4593 GLWD_STATIC_FILES_PATH=/usr/share/glewlwyd/webapp [...] glewlwyd --env-variables
```

By default, Glewlwyd is available on TCP port 4593.

## Getting started with the application

When your instance is up and running, you can complete its configuration with the [getting started documentation](GETTING_STARTED.md).

## Running Glewlwyd in test mode for integration tests

### Option 1 - Build your own Glewlwyd in test mode

You can create a Glewlwyd instance suited for integration tests. You need to build Glewlwyd with Mock modules and use a database initialized with the script [glewlwyd-test.sql](../test/glewlwyd-test.sql) after the script [docs/database/init.*.sql](database/). You can use 

```shell
$ # example with sqlite3 database
$ mkdir build && cd build
$ cmake -DWITH_MOCK=on ..
$ make && sudo make install
$ cd ..
$ sqlite3 /tmp/glewlwyd.db < docs/database/init.sqlite3.sql
$ sqlite3 /tmp/glewlwyd.db < test/glewlwyd-test.sql
$ glewlwyd --config-file=test/glewlwyd-ci.conf
```

### Option 2 - Glewlwyd in test mode on a Docker image

The docker build file [Dockerfile-ci](../Dockerfile-ci) builds and generates a docker image called `babelouest/glewlwyd:ci`. This docker image will execute Glewlwyd in test mode.

- Build the Docker image for test mode

```shell
$ make docker-ci
```

- Run the Docker image for test mode

```shell
$ docker run --rm -it -p 4593:4593 babelouest/glewlwyd:ci
```

### Glewlwyd in test mode configuration

When you run Glewlwyd in test mode, the Glewlwyd instance uses the mdules mock for client and user backend. These backends come with built-in users and clients. The instance also comes with preconfigured OAuth2 and OIDC plugins installed.

- The external url for this instance is: `http://localhost:4593`
- 3 mock schemes are instaciated:
  - `mock_scheme_42`, expected value to authenticate: `42`
  - `mock_scheme_88`, expected value to authenticate: `88`
  - `mock_scheme_95`, expected value to authenticate: `95`
- The scopes available are:
  - `g_admin`: access to administraiton page, available using password only, session timeout 600 seconds
  - `g_profile`: access to profile page, available using password only, session timeout 600 seconds
  - `openid`: available using any authentication, no session timeout
  - `scope1`: available using password and schemse (`mock_scheme_42` OR `mock_scheme_88`) AND `mock_scheme_95`, no session timeout
  - `scope2`: available using password and scheme `mock_scheme_95`, no session timeout
  - `scope3`: available using password and scheme `mock_scheme_88`, no session timeout

#### Mock users list

You can add, edit or remove any user from this backend instance, but there is no persistence, which means that if you restart Glewlwyd, the user list will be back to its original state. All users use the password `password`. The password is common for all users, which means that if you change the password for a user, the change will apply for all users.

- username: `admin`
  - password: `password`
  - name: `The Boss`
  - e-mail: `boss@glewlwyd.domain`
  - scopes: `g_admin`, `g_profile`, `openid`

- username: `user1`
  - password: `password`
  - name: `Dave Lopper 1`
  - e-mail: `dev1@glewlwyd.domain`
  - scopes: `g_profile`, `openid`, `scope1`, `scope2`, `scope3`

- username: `user2`
  - password: `password`
  - name: `Dave Lopper 2`
  - e-mail: `dev2@glewlwyd.domain`
  - scopes: `g_profile`, `openid`, `scope1`

- username: `user3`
  - password: `password`
  - name: `Dave Lopper 3`
  - e-mail: `dev3@glewlwyd.domain`
  - scopes: `g_profile`, `scope1`, `scope2`, `scope3`

#### Mock clients list

You can add, edit or remove any client from this backend instance, but there is no persistence, which means that if you restart Glewlwyd, the client list will be back to its original state.

- client_id: `client1_id`
  - name: `client1`
  - description: `Client mock 1`
  - confidential: `false`
  - authorization_type: `code`, `token`, `id_token`, `none`, `refresh_token`, `delete_token`
  - redirect_uri:
    - `../../test-oauth2.html?param=client1_cb1`
    - `../../test-oauth2.html?param=client1_cb2`
    - `../../test-oidc.html?param=client1_cb1`
  - sector_identifier_uri: `https://sector1.glewlwyd.tld`
  - scope: <none>

- client_id: `client2_id`
  - name: `client2`
  - description: `Client mock 2`
  - confidential: `false`
  - authorization_type: `code`
  - redirect_uri:
    - `../../test-oauth2.html?param=client2`
  - sector_identifier_uri: <none>
  - scope: <none>

- client_id: `client3_id`
  - name: `client3`
  - description: `Client mock 3`
  - confidential: `true`
  - password: `password`
  - authorization_type: `code`, `token`, `id_token`, `client_credentials`, `none`, `refresh_token`, `delete_token`
  - redirect_uri:
    - `../../test-oauth2.html?param=client3`
    - `../../test-oidc.html?param=client3`
  - sector_identifier_uri: `https://sector1.glewlwyd.tld`
  - scope: `scope2`, `scope3`

- client_id: `client4_id`
  - name: `client4`
  - description: `Client mock 4`
  - confidential: `true`
  - client_secret: `secret`
  - authorization_type: `code`, `token`, `id_token`
  - redirect_uri:
    - `../../test-oidc.html?param=client4`
  - sector_identifier_uri: `https://sector4.glewlwyd.tld`
  - scope: `scope2`, `scope3`

#### OAuth2 plugin instance

The non specified configuration values are the default ones

- name: `glwd`
- Display Name: `OAuth2 Glewlwyd plugin`
- URL API Auth for this instance: `http://localhost:4593/api/glwd/auth`
- URL API Token for this instance: `http://localhost:4593/api/glwd/token`
- URL API Profile for this instance: `http://localhost:4593/api/glwd/profile`
- Tokens signature
  - JWT Type: `SHA`
  - Key size: `256 bits`
  - Secret key: `secret`

#### OIDC plugin instance

The non specified configuration values are the default ones

- name: `oidc`
- Display Name: `OpenID Connect Glewlwyd plugin`
- URL openid-configuration for this instance: `http://localhost:4593/api/oidc/.well-known/openid-configuration`
- URL API Auth for this instance: `http://localhost:4593/api/oidc/auth`
- URL API Token for this instance: `http://localhost:4593/api/oidc/token`
- URL userinfo for this instance: `http://localhost:4593/api/oidc/userinfo`
- Issuer: `https://glewlwyd.tld`
- Allow passing request parameter as JWT: `true`
- Supported scopes: `openid`
- Tokens signature
  - JWT Type: `SHA`
  - Key size: `256 bits`
  - Secret key: `secret`
- Allow non OIDC but valid OAuth2 requests: `true`
- Authentication types enabled: `code`, `token`, `id_token`, `password`, `client_credentials`, `none`, `refresh_token`, `delete_token`

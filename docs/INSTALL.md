# Installation

1. [Distribution packages](#distribution-packages)
2. [Pre-compiled packages](#pre-compiled-packages)
   * [Install Glewlwyd on Debian Stretch](#install-glewlwyd-on-debian-stretch)
   * [Install Glewlwyd on Raspbian Stretch for Raspberry Pi](#install-glewlwyd-on-raspbian-stretch-for-raspberry-pi)
   * [Install Glewlwyd on Debian Buster](#install-glewlwyd-on-debian-buster)
   * [Install Glewlwyd on Ubuntu 18.04 LTS Bionic](#install-glewlwyd-on-ubuntu-1804-lts-bionic)
   * [Install Glewlwyd on Ubuntu 19.04 Disco](#install-glewlwyd-on-ubuntu-1904-disco)
3. [Docker](#docker)
4. [Manual install from source](#manual-install-from-source)
   * [Dependencies](#dependencies)
   * [Build Glewlwyd and its dependencies](#build-glewlwyd-and-its-dependencies)
5. [Configure glewlwyd.conf](#configure-glewlwydconf)
   * [external_url](#external_url)
   * [SSL/TLS](#ssltls)
   * [Digest algorithm](#digest-algorithm)
   * [Database back-end initialisation](#database-back-end-initialisation)
   * [Mime types for webapp files](#mime-types-for-webapp-files)
   * [Install as a service](#install-as-a-service)
6. [Initialise database](#initialise-database)
7. [Install as a service](#install-as-a-service)
8. [Fail2ban filter](#fail2ban-filter)
9. [Front-end application](#front-end-application)
10. [Run Glewlwyd](#run-glewlwyd)

### Distribution packages

[![Packaging status](https://repology.org/badge/vertical-allrepos/glewlwyd.svg)](https://repology.org/metapackage/glewlwyd)

Glewlwyd 1.x is available in Debian based distributions as official package. Check out your distribution documentation to install the package automatically.

```shell
$ # Example for Ubuntu 19.04
$ apt install glewlwyd
```

### Pre-compiled packages

You can install Glewlwyd with a pre-compiled package available in the [release pages](https://github.com/babelouest/glewlwyd/releases/). The package files `glewlwyd-full_*` contain the package libraries of `orcania`, `yder`, `ulfius` and `hoel` pre-compiled for `glewlwyd`, plus `glewlwyd` package. To install a pre-compiled package, you need the following libraries installed:

```
libmicrohttpd
libjansson
libcurl
libldap2
libmariadbclient
libsqlite3
libconfig
libgnutls
libjwt
liboath
libcbor
```

#### Install Glewlwyd on Debian Buster

```shell
$ sudo apt install -y libjansson4 libjwt0 libcbor0 libsqlite3-0 default-mysql-client libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.0.0-rc2/glewlwyd-full_2.0.0-rc2_debian_buster_x86_64.tar.gz
$ tar xf glewlwyd-full_2.0.0-rc2_debian_buster_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.0.1_debian_buster_x86_64.deb
$ sudo dpkg -i libyder_1.4.8_debian_buster_x86_64.deb
$ sudo dpkg -i libhoel_1.4.11_debian_buster_x86_64.deb
$ sudo dpkg -i libulfius_2.6.3_debian_buster_x86_64.deb
$ sudo dpkg -i glewlwyd_2.0.0-rc2_debian_buster_x86_64.deb
```

#### Install Glewlwyd on Raspbian Stretch for Raspberry Pi

```shell
$ sudo apt install -y libjansson4 libjwt0 libcbor0 libsqlite3-0 default-mysql-client libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.0.0-b1/glewlwyd-full_2.0.0-rc2_raspbian_stretch_armv6l.tar.gz
$ tar xf glewlwyd-full_2.0.0-rc2_Debian_stretch_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.0.0_Debian_stretch_x86_64.deb
$ sudo dpkg -i libyder_1.4.6_Debian_stretch_x86_64.deb
$ sudo dpkg -i libhoel_1.4.11_Debian_stretch_x86_64.deb
$ sudo dpkg -i libulfius_2.6.1_Debian_stretch_x86_64.deb
$ sudo dpkg -i glewlwyd_2.0.0-rc2_Debian_stretch_x86_64.deb
```

#### Install Glewlwyd on Ubuntu 18.04 LTS Bionic

```shell
$ # Note: libjwt provided with Ubuntu 18.04 LTS Bionic is too old to work with Glewlwyd module Webauthn
$ sudo apt install -y autoconf libjansson-dev automake make cmake libtool libsqlite3-0 libmariadbclient18 libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0 libjwt0 libcbor0
$ wget https://github.com/benmcollins/libjwt/archive/v1.10.2.tar.gz -O libjwt.tar.gz
$ tar -zxvf libjwt.tar.gz
$ cd libjwt-1.10.2
$ autoreconf -i
$ ./configure --without-openssl
$ make && sudo make install
$ cd ..
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.0.0-rc2/glewlwyd-full_2.0.0-rc2_ubuntu_bionic_x86_64.tar.gz
$ tar xf glewlwyd-full_2.0.0-rc2_ubuntu_bionic_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.0.1_ubuntu_bionic_x86_64.deb
$ sudo dpkg -i libyder_1.4.8_ubuntu_bionic_x86_64.deb
$ sudo dpkg -i libhoel_1.4.11_ubuntu_bionic_x86_64.deb
$ sudo dpkg -i libulfius_2.6.3_ubuntu_bionic_x86_64.deb
$ sudo dpkg -i glewlwyd_2.0.0-rc2_ubuntu_bionic_x86_64.deb
```

#### Install Glewlwyd on Ubuntu 19.04 Disco

```shell
$ sudo apt install -y libjansson4 libjwt0 libcbor0 libsqlite3-0 default-mysql-client libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.0.0-rc2/glewlwyd-full_2.0.0-rc2_ubuntu_disco_x86_64.tar.gz
$ tar xf glewlwyd-full_2.0.0-rc2_ubuntu_disco_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.0.1_ubuntu_disco_x86_64.deb
$ sudo dpkg -i libyder_1.4.8_ubuntu_disco_x86_64.deb
$ sudo dpkg -i libhoel_1.4.11_ubuntu_disco_x86_64.deb
$ sudo dpkg -i libulfius_2.6.3_ubuntu_disco_x86_64.deb
$ sudo dpkg -i glewlwyd_2.0.0-rc2_ubuntu_disco_x86_64.deb
```

If there's no package available for your distribution, you can recompile it manually using `CMake` or `Makefile`.

## Docker

### Quickstart for tests only

Run the docker image `babelouest/glewlwyd_quickstart` hosted on docker cloud, example:

```shell
docker run --rm -it -p 4593:4593 babelouest/glewlwyd_quickstart
```

This image uses a sqlite3 database hosted inside the docker instance, so all data will be lost when the docker instance will be stopped.
In this instance, both configuration files `glewlwyd.conf` (backend) and `config.json` (frontend) are stored in `/etc/glewlwyd`.

You can overwrite the configuration files `glewlwyd.conf` and `config.json` by mounting a volume on `/etc/glewlwyd` when you run the docker image. Point this volume to a local directory on the host.

You can use the files [docker/config/glewlwyd.conf](docker/config/glewlwyd.conf) and [docker/config/config.json](docker/config/config.json) as a starting point to build your config files for docker.

```shell
docker run --rm -it -p 4593:4593 -v /path/to/your/config:/etc/glewlwyd babelouest/glewlwyd_quickstart
```

### Docker image builder

The directory [docker](docker) contains a Docker file to rebuild the docker image.

## Manual install from source

Download the [latest source tarball](https://github.com/babelouest/glewlwyd/releases/latest) or [git clone](https://github.com/babelouest/glewlwyd.git) from GitHub.

### Dependencies

On a Debian based distribution (Debian, Ubuntu, Raspbian, etc.), you can install those dependencies using the following command:

```shell
$ sudo apt-get install autoconf automake libtool libmicrohttpd-dev sqlite3 libsqlite3-dev default-libmysqlclient-dev libpq-dev libgnutls-dev libconfig-dev libssl-dev libldap2-dev liboath-dev
```

#### Journald logs

The library libsystemd-dev is required if you want to log messages in journald service. If you don't want or can't have journald, you can compile yder library without journald support. See [Yder documentation](https://github.com/babelouest/yder).

#### Libssl vs GnuTLS

Both libraries are mentioned required, but you can skip libssl if you run `./configure` when installing `libjwt` with the option `--without-openssl`. `gnutls` 3.5.8 minimum is required. For this documentation to be compatible with most Linux distributions, libssl isn't removed from the required libraries yet.

#### Libmicrohttpd bug on POST parameters

With Libmicrohttpd 0.9.37 and older version, there is a bug when parsing `application/x-www-form-urlencoded` parameters. This is fixed in later version, from the 0.9.38, so if your Libmicrohttpd version is older than that, I suggest getting a newer version of [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/).

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
- `-DWITH_JOURNALD=[on|off]` (default `on`): Build with journald (SystemD) support
- `-DCMAKE_BUILD_TYPE=[Debug|Release]` (default `Release`): Compile with debugging symbols or not
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
$ make DISABLE_POSTGRESQL=1
$ sudo make install

# Install Glewlwyd
$ git clone https://github.com/babelouest/glewlwyd.git
$ cd glewlwyd/src/
$ make 
$ sudo make install
```

## Configure glewlwyd

Glewlwyd requires several configuration variables to work. You can specify those variables in a configuration file, environment variables, or both. In addition, some variables can be set via command-line arguments.

The command-line arguments have the higher priority, followed by the environment variables, then the configuration file.

To run Glewlwyd with the config file, copy `glewlwyd.conf.sample` to `glewlwyd.conf`, edit the file `glewlwyd.conf` with your own settings.

The following paragraphs describe all the configuration parameters.

To enable environment variables in Glewlwyd, you must execute the program with the `-e` command-line argument.

### Port number

- Config file variable: `port`
- Environment variable: `GLWD_PORT`

Optional, The TCP port the service will listen to incoming cnnexions. The port number must be available to the user running Glewlwd process. Default value is 4593.

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

#### Client modules path

- Config file variable: `client_module_path`
- Environment variable: `GLWD_CLIENT_MODULE_PATH`

#### User auth scheme modules path

- Config file variable: `user_auth_scheme_module_path`
- Environment variable: `GLWD_AUTH_SCHEME_MODUE_PATH`

#### Plugin modules path

- Config file variable: `plugin_module_path`
- Environment variable: `GLWD_PLUGIN_MODULE_PATH`

Mandatory, path to modules.

### Digest algorithm

- Config file variable: `hash_algorithm`
- Environment variable: `GLWD_HASH_ALGORITHM`

Optional, default value is SHA256.

Specify in the config file the parameter `hash_algorithm` to store token and secret digests.

Algorithms available are SHA1, SHA256, SHA512, MD5. Algorithms recommended are SHA256 or SHA512.

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

This configuration is mandatory only if you want to use TLS Certificate authentication schemes, it must contain the CA certificate file used to authenticate clients certificates. Otherwise you can skip it.

If this option is set, users can still connect to Glewlwyd without TLS certificate.

- Config file variable: `secure_connection_ca_file`
- Environment variable: `GLWD_SECURE_CONNECTION_CA_FILE`

OAuth 2 specifies that a secured connection is mandatory, via SSL or TLS, to avoid data and token to be stolen, or Man-In-The-Middle attacks. Glewlwyd supports starting a secure connection with a private/public key certificate, but it also can be with a classic non-secure HTTP connection, and be available to users behind a HTTPS proxy for example. Glewlwyd won't check that you use it in a secure connection.

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
  path = "/tmp/glewlwyd.db"
}
# SQLite database environment variables
GLWD_DATABASE_TYPE must be set to "sqlite3"
GLWD_DATABASE_SQLITE3_PATH

# PostgreSQL database configuration file variables
database =
{
  type = "postgre"
  conninfo = "dbname = glewlwyd"
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
```shell
$ psql -Uglewlwyd -W -fdocs/database/init.postgre.sql
```

#### Security warning!

Those scripts create a valid database that allow to use glewlwyd. But to avoid potential security issues, you must change the admin password when you first connect to the application.

#### Built-in scope values

If you want to use a different name for admin scope (default is `g_admin`), or the profile scope (default is `g_profile`), you must update the init script with your own value before running it, change the lines below accordingly.

#### Administrator user

An administrator must be present in the back-end to manage the application (manage scopes, users, clients, resources, authorization types).

An administrator in the LDAP back-end is a user who has the `admin_scope` (default `g_admin`) in its scope list.

### Install as a service

The files `glewlwyd-init` (SysV init) and `glewlwyd.service` (Systemd) can be used to have glewlwyd as a daemon. They are fitted for a Raspbian distribution, but can easily be changed for other systems. It's highky recommended to run glewlwyd as a user without root access. Glewlwyd requires to be able top open a TCP port connection, a full access to the glewlwyd database, read access to the config file `glewlwyd.conf` and the installed `webapp/` folder (typically /usr/share/glewlwyd/webapp`.

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
$ sudo systemctl start glewlwyd
```

## Fail2ban filter

You can add specific filter for fail2ban to ban potential attackers.

The `glewlwyd.conf` file is available in [fail2ban/glewlwyd.conf](fail2ban/glewlwyd.conf). It will ban the IP addresses using the following rules:
- `Authorization invalid` - on a failed auth
- `Code invalid` - on a invalid code in OAuth2 or OIDC
- `Scheme email - code sent` - when an OTP code is sent via e-mail, to avoid spamming users

The `glewlwyd.conf` has the following content:

```config
# Fail2Ban filter for Glewlwyd
#
# Author: Nicolas Mora
#

[Definition]

failregex = ^.* - Glewlwyd WARNING: Security - Authorization invalid for username .* at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Code invalid at IP Address <HOST>
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
port     = http,https
```

Check out [Fail2ban](https://www.fail2ban.org/) documentation for more information.

## Front-end application

All front-end pages have a minimal design, feel free to modify them for your own need, or create your own application. The source code is available in `/webapp-src` and requires nodejs and npm or yarn to build.

The built front-end files are located in the webapp/ directory.

### webapp/config.json

The front-end configuration file must be available under `webapp/config.json` you can copy the file `webapp/config.json.sample`.

You must modify the urls of the API and the html page to match your configuration:

Example:

```Javascript
{
  "GlewlwydUrl": "https://glewlwyd.tld/",
  "ProfileUrl": "https://glewlwyd.tld/profile.html",
  "AdminUrl": "https://glewlwyd.tld/index.html",
  "LoginUrl": "https://glewlwyd.tld/login.html"
}
```

### Login, Admin and Profile pages

These pages are used when a user requires some access to Glewlwyd. They are simple html pages with a small JavaScript/JQuery application in it to provide the expected behavior, and vanilla bootstrap 4 for the visual consistency. Glewlwyd front-end source code is under license MIT. Fell free to update them to fit your needs or to adapt the front-end to your identity.

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

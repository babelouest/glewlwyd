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

Glewlwyd 1.x is available in Debian based distributions as official package. Check out your distribution documentation to install the package automatically.

```shell
$ # Example for Ubuntu 19.04
$ apt install glewlwyd
```

### Pre-compiled packages

You can install Glewlwyd with a pre-compiled package available in the [release pages](https://github.com/babelouest/glewlwyd/releases/). The package files `glewlwyd-full_*` contain the package libraries of `orcania`, `yder`, `ulfius` and `hoel` pre-compiled for `glewlwyd`, plus `glewlwyd` package. To install a pre-compiled package, you need to have installed the following libraries:

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

#### Install Glewlwyd on Debian Stretch

```shell
$ sudo apt install -y autoconf libjansson-dev automake make cmake libtool libsqlite3-0 libmariadbclient18 libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0
$ wget https://github.com/benmcollins/libjwt/archive/v1.10.2.tar.gz -O libjwt.tar.gz
$ tar -zxvf libjwt.tar.gz
$ cd libjwt-1.10.2
$ autoreconf -i
$ ./configure --without-openssl
$ make && sudo make install
$ cd ..

$ wget https://github.com/PJK/libcbor/archive/v0.5.0.tar.gz -O libcbor.tar.gz
$ tar xf libcbor.tar.gz
$ mkdir libcbor-0.5.0/build
$ cd libcbor-0.5.0/build
$ cmake ..
$ make && sudo make install
$ cd ../..
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.0.0-b1/glewlwyd-full_2.0.0-b1_debian_stretch_x86_64.tar.gz
$ tar xf glewlwyd-full_2.0.0_Debian_stretch_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.0.0_Debian_stretch_x86_64.deb
$ sudo dpkg -i libyder_1.4.6_Debian_stretch_x86_64.deb
$ sudo dpkg -i libhoel_1.4.10_Debian_stretch_x86_64.deb
$ sudo dpkg -i libulfius_2.6.1_Debian_stretch_x86_64.deb
$ sudo dpkg -i glewlwyd_2.0.0-b1_Debian_stretch_x86_64.deb
```

#### Install Glewlwyd on Raspbian Stretch for Raspberry Pi

```shell
$ sudo apt install -y autoconf libjansson-dev automake make cmake libtool libsqlite3-0 libmariadbclient18 libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0
$ wget https://github.com/benmcollins/libjwt/archive/v1.10.2.tar.gz -O libjwt.tar.gz
$ tar -zxvf libjwt.tar.gz
$ cd libjwt-1.10.2
$ autoreconf -i
$ ./configure --without-openssl
$ make && sudo make install
$ cd ..
$ wget https://github.com/PJK/libcbor/archive/v0.5.0.tar.gz -O libcbor.tar.gz
$ tar xf libcbor.tar.gz
$ mkdir libcbor-0.5.0/build
$ cd libcbor-0.5.0/build
$ cmake ..
$ make && sudo make install
$ cd ../..
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.0.0-b1/glewlwyd-full_2.0.0-b1_raspbian_stretch_armv6l.tar.gz
$ tar xf glewlwyd-full_2.0.0_Debian_stretch_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.0.0_Debian_stretch_x86_64.deb
$ sudo dpkg -i libyder_1.4.6_Debian_stretch_x86_64.deb
$ sudo dpkg -i libhoel_1.4.10_Debian_stretch_x86_64.deb
$ sudo dpkg -i libulfius_2.6.1_Debian_stretch_x86_64.deb
$ sudo dpkg -i glewlwyd_2.0.0-b1_Debian_stretch_x86_64.deb
```

#### Install Glewlwyd on Debian Buster

```shell
$ sudo apt install -y autoconf libjansson-dev automake make cmake libtool libsqlite3-0 libmariadbclient18 libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0 libjwt0 libcbor0
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.0.0-b1/glewlwyd-full_2.0.0-b1_debian_buster_x86_64.tar.gz
$ tar xf glewlwyd-full_2.0.0_Debian_buster_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.0.0_Debian_buster_x86_64.deb
$ sudo dpkg -i libyder_1.4.6_Debian_buster_x86_64.deb
$ sudo dpkg -i libhoel_1.4.10_Debian_buster_x86_64.deb
$ sudo dpkg -i libulfius_2.6.1_Debian_buster_x86_64.deb
$ sudo dpkg -i glewlwyd_2.0.0-b1_Debian_buster_x86_64.deb
```

#### Install Glewlwyd on Ubuntu 18.04 LTS Bionic

```shell
$ sudo apt install -y autoconf libjansson-dev automake make cmake libtool libsqlite3-0 libmariadbclient18 libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0 libjwt0 libcbor0
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.0.0-b1/glewlwyd-full_2.0.0-b1_ubuntu_bionic_x86_64.tar.gz
$ tar xf glewlwyd-full_2.0.0_Ubuntu_bionic_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.0.0_Ubuntu_bionic_x86_64.deb
$ sudo dpkg -i libyder_1.4.6_Ubuntu_bionic_x86_64.deb
$ sudo dpkg -i libhoel_1.4.10_Ubuntu_bionic_x86_64.deb
$ sudo dpkg -i libulfius_2.6.1_Ubuntu_bionic_x86_64.deb
$ sudo dpkg -i glewlwyd_2.0.0-b1_Ubuntu_bionic_x86_64.deb
```

#### Install Glewlwyd on Ubuntu 19.04 Disco

```shell
$ sudo apt install -y autoconf libjansson-dev automake make cmake libtool libsqlite3-0 libmariadbclient18 libpq5 libgnutls30 libconfig9 libldap-2.4-2 liboath0 libjwt0 libcbor0
$ wget https://github.com/babelouest/glewlwyd/releases/download/v2.0.0-b1/glewlwyd-full_2.0.0-b1_ubuntu_disco_x86_64.tar.gz
$ tar xf glewlwyd-full_2.0.0_Ubuntu_disco_x86_64.tar.gz
$ sudo dpkg -i liborcania_2.0.0_Ubuntu_disco_x86_64.deb
$ sudo dpkg -i libyder_1.4.6_Ubuntu_disco_x86_64.deb
$ sudo dpkg -i libhoel_1.4.10_Ubuntu_disco_x86_64.deb
$ sudo dpkg -i libulfius_2.6.1_Ubuntu_disco_x86_64.deb
$ sudo dpkg -i glewlwyd_2.0.0-b1_Ubuntu_disco_x86_64.deb
```

If there's no package available for your distribution, you can recompile it manually using `CMake` or `Makefile`.

## Docker

TBD

## Manual install from Github

On a Debian based distribution (Debian, Ubuntu, Raspbian, etc.), you can install those dependencies using the following command:

```shell
$ sudo apt-get install autoconf automake libtool sqlite3 libsqlite3-dev default-libmysqlclient-dev libpq-dev libgnutls-dev libconfig-dev libssl-dev libldap2-dev liboath-dev
```

#### Journald logs

The library libsystemd-dev is required if you want to log messages in journald service. If you don't want or can't have journald, you can compile yder library without journald support. See [Yder documentation](https://github.com/babelouest/yder).

### Libssl vs GnuTLS

Both libraries are mentioned required, but you can get rid of libssl if you install `libjwt` with the option `--without-openssl`. `gnutls` 3.5.8 minimum is required. For this documentation to be compatible with most Linux distributions (at least the one I use), I don't remove libssl from the required libraries yet.

### Libmicrohttpd bug on POST parameters

With Libmicrohttpd 0.9.37 and older version, there is a bug when parsing `application/x-www-form-urlencoded` parameters. This is fixed in later version, from the 0.9.38, so if your Libmicrohttpd version is older than that, I suggest getting a newer version of [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/).

### Build Glewlwyd and its dependencies

#### CMake

Download and install libjwt, then download Glewlwyd from GitHub, then use the CMake script to build the application:

```shell
# Install libjwt if not present in your package manager, libjwt 1.10 minimum is required
# libtool and autoconf are required
$ wget https://github.com/benmcollins/libjwt/archive/v1.10.2.tar.gz -O libjwt-1.10.2.tar.gz
$ tar xzf libjwt-1.10.2.tar.gz
$ cd libjwt-1.10.2 && autoreconf -i && ./configure && make && sudo make install # use ./configure --without-openssl to use gnutls instead, you must have gnutls 3.5.8 minimum
$ rm -rf libjwt-1.10.2
$ sudo ldconfig
$ cd ..

# Install libcbor
$ wget https://github.com/PJK/libcbor/archive/v0.5.0.tar.gz -O libcbor.tar.gz
$ tar xf libcbor.tar.gz
$ mkdir libcbor-0.5.0/build
$ cd libcbor-0.5.0/build
$ cmake ..
$ make && sudo make install
$ cd ../..

# Install Glewlwyd
$ git clone https://github.com/babelouest/glewlwyd.git
$ mkdir glewlwyd/build
$ cd glewlwyd/build
$ cmake ..
$ make 
$ sudo make install
```

### Good ol' Makefile

Download Glewlwyd and its dependencies hosted on GitHub, compile and install.

```shell
# Install libjwt if not present in your package manager, libjwt 1.10 minimum is required
# libtool and autoconf are required
$ wget https://github.com/benmcollins/libjwt/archive/v1.10.2.tar.gz -O libjwt-1.10.2.tar.gz
$ tar xzf libjwt-1.10.2.tar.gz
$ cd libjwt-1.10.2 && autoreconf -i && ./configure && make && sudo make install # use ./configure --without-openssl to use gnutls instead, you must have gnutls 3.5.8 minimum
$ rm -rf libjwt-1.10.2
$ sudo ldconfig
$ cd ..

# Install libcbor
$ wget https://github.com/PJK/libcbor/archive/v0.5.0.tar.gz -O libcbor.tar.gz
$ tar xf libcbor.tar.gz
$ mkdir libcbor-0.5.0/build
$ cd libcbor-0.5.0/build
$ cmake ..
$ make && sudo make install
$ cd ../..

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

## Configure glewlwyd.conf

Copy `glewlwyd.conf.sample` to `glewlwyd.conf`, edit the file `glewlwyd.conf` with your own settings.

### SSL/TLS

OAuth 2 specifies that a secured connection is mandatory, via SSL or TLS, to avoid data and token to be stolen, or Man-In-The-Middle attacks. Glewlwyd supports starting a secure connection with a private/public key certificate, but it also can be with a classic non-secure HTTP connection, and be available to users behind a HTTPS proxy for example. Glewlwyd won't check that you use it in a secure connection.

### Digest algorithm

Specify in the config file the parameter `hash_algorithm` to store passwords with sqlite3 back-end, and token digests.

Algorithms available are SHA1, SHA256, SHA512, MD5. Algorithms recommended are SHA256 or SHA512.

### Database back-end initialisation

Configure your database backend according to the database you will use.

```
# MariaDB/Mysql database connection
database =
{
  type     = "mariadb"
  host     = "localhost"
  user     = "glewlwyd"
  password = "glewlwyd"
  dbname   = "glewlwyd"
  port     = 0
}

# SQLite database connection
database =
{
  type = "sqlite3"
  path = "/tmp/glewlwyd.db"
};

# PostgreSQL database connection
database =
{
  type = "postgre"
  conninfo = "dbname = glewlwyd"
}
```

### Mime types for webapp files

This section in the config file is used by the static file service whuch will provide the `webapp/` content to the browser. You can add or remove values if you made changes to the front-end and requires to handle new types of files.

## Configure webapp/config.json

Copy `webapp/config.json.sample` to `webapp/config.json`, edit the file with your own settings.

### GlewlwydApiUrl, ProfileUrl, AdminUrl and LoginUrl

Update those parameters to fit your configuration.

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
$ sqlite3 /var/cache/glewlwyd/glewlwyd.db < database/init.sqlite3.sql
```

#### Security warning!

Those scripts create a valid database that allow to use glewlwyd but to avoid potential security issues, you must change the admin password when you first connect to the application.

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

All front-end pages have a minimal design, feel free to modify them for your own need, or create your own application. The source code is available in `/webapp-src` and requires nodejs and npm or yarn to build.

The built front-end files are located in the webapp/ directory.

### Login, Admin and Profile pages

These pages are used when a user requires some access to Glewlwyd. They are simple html pages with a small JavaScript/JQuery application in it to provide the expected behavior, and vanilla bootstrap 4 for the visual consistency. Glewlwyd front-end source code is under license MIT. Fell free to update them to fit your needs or to adapt the front-end to your identity.

# Glewlwyd Oauth 2 authentication server

[Oauth 2](https://oauth.net/2/) Server providing [JSON Web Tokens](https://jwt.io/) for identification.

Lightweight, fast and easy to install on small systems. Requires a MySql or SQLite3 database. Handles LDAP or database for users backend.

Fully written in C language, based on [Ulfius](https://github.com/babelouest/ulfius) HTTP framework, [Hoel](https://github.com/babelouest/hoel) database framework and [Libjwt](https://github.com/benmcollins/libjwt.git) JSON Web Tokens library.

Beware! It's still a work in progress, not fully completed yet, and with probably a lot of bugs.

The authentication part is available, which means that the OAuth2 RFC is implemented, but not (yet) the users/clients/scope administration pages and APIs.

## Installation

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
libssl
```

On a Debian based distribution (Debian, Ubuntu, Raspbian, etc.), you can install those dependencies using the following command:

```shell
$ sudo apt-get install libmicrohttpd-dev libjansson-dev libcurl4-gnutls-dev uuid-dev libldap2-dev libmysqlclient-dev libsqlite3-dev libconfig-dev libssl-dev
```

### Debian stable distributions libmicrohttpd bug

I've noticed that on a Debian stable, libmicrohttpd has a bug when it parses `application/x-www-form-urlencoded` parameters. This is fixed in later version, so I suggest using the latest stable version of [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/).

Then, download Glewlwyd and its dependendencies hosted in github, compile and install.

```shell
# Install libjwt
$ git clone https://github.com/benmcollins/libjwt.git
$ cd libjwt/
$ autoreconf -i
$ ./configure
$ make
$ sudo make install

# Install Ulfius
$ git clone https://github.com/babelouest/ulfius.git
$ cd ulfius/
$ git submodule update --init
$ make
$ sudo make install

# Install Hoel
$ git clone https://github.com/babelouest/hoel.git
$ cd hoel/
$ make
$ sudo make install

# Install Glewlwyd
$ git clone https://github.com/babelouest/glewlwyd.git
$ cd glewlwyd
$ make 
$ sudo make install
```

## Configuration

Copy `glewlwyd.conf.sample` to `glewlwyd.conf`, edit the file `glewlwyd.conf` with your own settings.

### Data storage backend initialisation

You can use a MySql/MariaDB database or a SQLite3 database file.
You can use the dedicated script to initialize your database.

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

### Authentication backend configuration

For the authentication backend, you can use a LDAP server or your database, or both. If you use both backends, then on an authentication process, the user will be tested in the LDAP first, then in the database.

The database authentication is built-in, there's nothing to configure. The LDAP authentication must be properly set though.

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

### Login and grant pages

Login and grant access pages example are available in the `webapp` folder to properly use Glewlwyd.

## Usage

By default, Glewlwyd is available on TCP port 4593. There's a test page in `webapp/index.html` to validate the behaviour. You can access it using the url: [http://localhost:4593/app/](http://localhost:4593/app/).

## SSL/TLS

OAuth 2 specifies that a secured connection is mandatory, via SSL or TLS, to avoid data and token to be stolen, or Man-In-The-Middle attacks. Glewlwyd supports starting a secure connection with a private/public key certificate, but it also can be with a classic non-secure HTTP connection, and be available to users behind a HTTPS proxy.

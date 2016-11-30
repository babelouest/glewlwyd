# Glewlwyd Oauth 2 authentication server

[Oauth 2](https://oauth.net/2/) Server providing [Json Web Tokens](https://jwt.io/) for identification.

Lightweight, fast and easy to install on small systems. Requires a MySql or SQLite3 database. Handles LDAP or database for users backend.

Fully written in C language, based on [Ulfius](https://github.com/babelouest/ulfius) HTTP framework, [Hoel](https://github.com/babelouest/hoel) database framework and [Libjwt](https://github.com/benmcollins/libjwt.git) library.

## Installation

Download Glewlwyd and its dependendencies, compile and install.

```shell
$ sudo apt-get install libmicrohttpd-dev libjansson-dev libcurl4-gnutls-dev uuid-dev libldap2-dev libmysqlclient-dev libsqlite3-dev libconfig-dev libssl-dev

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

# Install glewlwyd
$ git clone https://github.com/babelouest/glewlwyd.git
$ cd glewlwyd
$ make 
$ sudo make install
```

## Usage

Work in progress...

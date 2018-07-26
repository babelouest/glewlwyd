# Glewlwyd Oauth 2 authentication server

[![Build Status](https://travis-ci.com/babelouest/glewlwyd.svg?branch=master)](https://travis-ci.com/babelouest/glewlwyd)

Single Sign On [Oauth 2](https://oauth.net/2/) authentication server.

This is the development branch for the next release 2.0. The next release is currently under development.

See issue #35 (Glewlwyd 2.0 Roadmap) for the general architecture and design.

A beta release will come out when it's ready, any help is welcome!

The API backend is fully written in C language, it's based on [Ulfius](https://github.com/babelouest/ulfius) HTTP framework, [Hoel](https://github.com/babelouest/hoel) database framework and [Libjwt](https://github.com/benmcollins/libjwt.git) JSON Web Tokens library.

![user list screenshot](https://raw.githubusercontent.com/babelouest/glewlwyd/master/screenshots/g_1_users.png)

## Installation

Please read the [docs/INSTALL.md](docs/INSTALL.md) file for more information.

## Screenshots

Some screenshots examples:

![User details page](https://github.com/babelouest/glewlwyd/raw/master/screenshots/g_2_user_details.png)

![User update](https://github.com/babelouest/glewlwyd/raw/master/screenshots/g_1_users_udate.png)

![Clients list page](https://github.com/babelouest/glewlwyd/raw/master/screenshots/g_3_clients.png)

![Client update](https://github.com/babelouest/glewlwyd/raw/master/screenshots/g_3_clients_update.png)

![Scopes list](https://github.com/babelouest/glewlwyd/raw/master/screenshots/g_4_scopes.png)

![Authorization types](https://github.com/babelouest/glewlwyd/raw/master/screenshots/g_6_auth_types.png)

### Current user

All users can also update their own profile with the dedicated page `profile.html`.

![User profile page](https://github.com/babelouest/glewlwyd/raw/master/screenshots/profile.png)

![Update user profile password](https://github.com/babelouest/glewlwyd/raw/master/screenshots/profile_upate_password.png)

The pages `login.html`, `grant.html` and `reset.html` are tiny pages used to login, logout, grant scope access or reset a password.

![login](https://github.com/babelouest/glewlwyd/raw/master/screenshots/sign_in.png)

![reset](https://github.com/babelouest/glewlwyd/raw/master/screenshots/password_forgot.png)

If a user uses the reset password functionality, he or she will receive the content of the file `reset.eml`. The email uses two patterns that will be replaced by values: `$USERNAME` for the username and `$URL` for the url to the reset.html page.

`$URL` must be set in the configuration file properly so the emails will lead to the correct page.

More screenshots of the front-end application are available in the [screenshot](https://github.com/babelouest/glewlwyd/tree/master/screenshots) folder.

## Projects using Glewlwyd as authentication server

Glewlwyd front-end applications uses glewlwyd to authenticate of course, but other projects are also using it to delegate the authentication and focus on their goals:

- [Taliesin](https://github.com/babelouest/taliesin), an audio streaming server

- [Angharad](https://github.com/babelouest/angharad), a house automation server to connect and control IOT devices using different protocols (Zwave, Taulas, etc.)

- [Hutch](https://github.com/babelouest/hutch), an online password manager

## Questions, problems or feature requests

You can open an [issue](https://github.com/babelouest/glewlwyd/issues) in github or send me an [e-mail](mailto:mail@babelouest.org). Any help is much appreciated!

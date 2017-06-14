# Glewlwyd Oauth 2 authentication server

[Oauth 2](https://oauth.net/2/) Server providing [JSON Web Tokens](https://jwt.io/) for identification.

Lightweight, fast and easy to install on small systems. Requires a MySql or SQLite3 database. Handles LDAP or database for users backend.

The API backend is fully written in language C, it's based on [Ulfius](https://github.com/babelouest/ulfius) HTTP framework, [Hoel](https://github.com/babelouest/hoel) database framework and [Libjwt](https://github.com/benmcollins/libjwt.git) JSON Web Tokens library.

![user list screenshot](https://raw.githubusercontent.com/babelouest/glewlwyd/master/screenshots/g_1_users.png)

## Installation

Please read the [INSTALL.md](INSTALL.md) file for more information.

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

If a user uses the reset password functionnality, he or she will receive the content of the file `reset.eml`. The email uses two patterns that will be replaced by values: `$USERNAME` for the username and `$URL` for the url to the reset.html page.

`$URL` must be set in the configuration file properly so the emails will lead to the correct page.

More screenshots of the front-end application are availabe in the [screenshot](https://github.com/babelouest/glewlwyd/tree/master/screenshots) folder.

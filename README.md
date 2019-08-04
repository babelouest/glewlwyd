# Glewlwyd SSO server

[![Build Status](https://travis-ci.com/babelouest/glewlwyd.svg?branch=master)](https://travis-ci.com/babelouest/glewlwyd)

Single Sign On authentication server. Provides OpenID Connect and basic OAuth2 authentication processus and allows users to authenticate via multiple factors:
- Password
- One-time password (TOTP/HOTP)
- Webauthn (Yubikey or Android safetynet)
- Random Code sent via e-mail

Allows no-password authentication.

Users are stored in multiple backends such as database or LDAP server.

adding new authentication schemes or backend storage for users and clients is possible via a plugin architecture.

![logged in](docs/screenshots/login-nopassword.png)

Glewlwyd 2.0 Beta 3 is out. Glewlwyd 2.0 is not complete yet but you can install the Beta version, check out the new features and send feedbacks if you feel like it.

Important! Due to database reworking of the application, you can't upgrade an existing installation from Glewlwyd 1.x to Glewlwyd 2.x.

## Installation

The full installation documentation is available in the [install documentation](docs/INSTALL.md).

## Getting started

The [Getting started documentation](docs/GETTING_STARTED.md) will help you complete the installation of Glewlwyd.

## User documentation

The [documentation](docs/USER.md) to help Glewlwyd's users manage their profile and log in to Glewlwyd is available.

## Core API

The full core API documention is available in the [API documentation](docs/API.md)

## Screenshots

Go to the [Screenshots](docs/screenshots) folder.

## Questions, problems or feature requests

You can open an [issue](https://github.com/babelouest/glewlwyd/issues) in github or send me an [e-mail](mailto:mail@babelouest.org). Any help is much appreciated!

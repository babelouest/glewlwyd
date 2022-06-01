# Glewlwyd SSO server

![C/C++ CI](https://github.com/babelouest/glewlwyd/workflows/C/C++%20CI/badge.svg)
![CodeQL](https://github.com/babelouest/glewlwyd/workflows/CodeQL/badge.svg)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/3475/badge)](https://bestpractices.coreinfrastructure.org/projects/3475)

## Single-Sign-On (SSO) server with multiple factor authentication for OAuth2 and OpenID Connect authentication

**[Glewlwyd 2.7.0 is available](https://github.com/babelouest/glewlwyd/releases/latest). Feel free to [install](docs/INSTALL.md) it, test it, use it, and [send feedback](https://github.com/babelouest/glewlwyd/issues) if you feel like it!**

**Go to the [online demo](https://babelouest.io/glewlwyd) to test Glewlwyd's features**

![logged in](docs/screenshots/login-nopassword.png)

## Process supported:
- [OpenID Connect/OAuth2](docs/OIDC.md)
- [OAuth2](docs/OAUTH2.md): Legacy plugin, it's recommended to use the OpenID Connect/OAuth2 for new installations

## User authentication via multiple factors:
- [Password](https://xkcd.com/936/)
- [One-time password (TOTP/HOTP)](docs/OTP.md)
- [WebAuthn (Yubikey, Android and Apple fingerprint or face id, etc.)](docs/WEBAUTHN.md)
- [One-time password sent via e-mail](docs/EMAIL.md)
- [TLS Certificate](docs/CERTIFICATE.md)
- [External OAuth2/OIDC providers](docs/OAUTH2_SCHEME.md)
- [HTTP Backend service providing Basic Authentication](docs/HTTP.md)

## Users and clients can be storage backends:
- [Database](docs/USER_DATABASE.md)
- [LDAP service](docs/USER_LDAP.md)
- [HTTP Backend service providing Basic Authentication](docs/USER_HTTP.md) (Users only)

## User registration

New users can [register a new account](docs/REGISTER.md) with the possibility to confirm their e-mail address or not. During the registration process, the new user may be expected to register their passwords, as well as other authentication factors:
- One-time password (TOTP/HOTP)
- WebAuthn (Yubikey, Android devices)
- TLS Certificate
- External OAuth2/OIDC providers

Existing users can update their e-mail by sending a confirmation link to the new e-mail.

## Lost credentials

Existing users can reset their credentials if their password or authentication schemes are lost or unavailable. Credentials can be reset by different factors:
- A link sent to the user's e-mail
- A one-time use recovery code

See the [register/update e-mail/reset credentials documentation](docs/REGISTER.md) for more information on the registration, update e-mail or reset credentials features.

Based on a plugin architecture to make it easier to add or update storage backends, authentication schemes or process.

## Passwordless authentication

Adding new authentication schemes or backend storage for users and clients is possible via the plugin architecture.

## Architecture and performance

The backend API server is fully written in C and uses a small amount of resources.

Its plugin architecture makes it easy to add new modules or plugins, or modify existing ones with less risks to have unmaintainable code.

## Disclaimer

Glewlwyd is mostly developped by myself on my free time, with gracious help from users.

Nevertheless, it hasn't been audited or fully tested by external developpers.

Glewlwyd can take a central place in a system where applications and environments need authentication and authorization, be aware of the risks: bugs, non discovered vulnerabilities, etc.

I recommend not to use Glewlwyd in production, more likely to test OAuth2/OpenID behavior, MFA connections, or IdP in general. You can also explore its functionalities and help yourself with its source code for other implementations.

If you intent to use it in production, it's highly recommended to follow the documentation and enable only the features you will use.

# Installation

The full installation documentation is available in the [Install documentation](docs/INSTALL.md).

## Docker

A docker image is available for tests on localhost. To test the image, run the following command:

```shell
$ docker run --rm -it -p 4593:4593 babelouest/glewlwyd:latest
```

And open the address [http://localhost:4593/](http://localhost:4593/) on your browser.

- User: `admin`
- Password: `password`

This Docker image can be used for tests or for real use by changing the configuration files. More information in the [install documentation](docs/INSTALL.md#docker).

## Getting started

The [Getting started documentation](docs/GETTING_STARTED.md) will help administrators configure Glewlwyd's modules and authentication schemes.

## User documentation

The [user documentation](docs/USER.md) will help Glewlwyd's users manage their profile and log in to Glewlwyd.

## Core API

The full core REST API documentation is available in the [API documentation](docs/API.md)

## Plugins architecture

You can update the existing plugins or add new ones depending on your needs, check out the documentation available for each type of plugin:
- [User backend modules](src/user/)
- [User middleware backend modules](src/user_middleware/)
- [Client backend modules](src/client/)
- [Authentication schemes modules](src/scheme/)
- [Plugins](src/plugin/) (Register, OAuth2 or OIDC plugins)

## Screenshots

Go to the [Screenshots](docs/screenshots) folder to get a visual idea of Glewlwyd.

## Questions, problems or feature requests

You can open an [issue](https://github.com/babelouest/glewlwyd/issues), a [pull request](https://github.com/babelouest/ulfius/pulls) or send me an [e-mail](mailto:mail@babelouest.io). Any help is much appreciated!

You can visit the IRC channel #glewlwyd on the [Libera.​Chat](https://libera.chat/) network.

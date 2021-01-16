# Glewlwyd Changelog

## 2.5.1

- Add `identify` action to authenticate via schemes oauth2 or certificate without giving the username
- Fix change password issue in the admin interface
- Add oidc config `restrict-scope-client-property` to restrict a client to certain scopes if needed

## 2.5.0

The `"Recontainment Release"`

- Fix `aud` property to fit JWT access token spec
- Add support for OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer (DPoP) [Draft 01](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop-01)
- Allow multiple passwords for users
- Implement [Resource Indicators for OAuth 2.0](https://tools.ietf.org/html/rfc8707) for OIDC plugin
- Implement [Content-Encoding](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding) to compress response bodies using `gzip` or `deflate` when relevant
- Implement [OAuth 2.0 Rich Authorization Requests Draft 03](https://www.ietf.org/archive/id/draft-ietf-oauth-rar-03.html)
- Implement [OAuth 2.0 Pushed Authorization Requests Draft 05](https://tools.ietf.org/html/draft-ietf-oauth-par-05)

## 2.4.0

The `"Second Wave Release"`

- Allow user to update its e-mail
- Allow user to reset its credentials
- Handle callback url for registration and reset credentials
- Update certificate scheme management: remove online certiticate generation and add certificate validation via DN
- Implement revoke tokens on code replay for oauth2 and oidc plugins
- Show `client_id` and `redirect_uri` on grant scope
- Remove `parameters` object on `*_load()` functions result
- Scheme WebAuthn: disable fmt `none` by default
- Allow to add granted scope list in `id_token` and `/userinfo`
- Fix last login refresh without authentication bug
- Add endpoint `/mod/reload/` to reload modules lists
- Add Event log messages
- Add parameter Scheme Required to a scope scheme group
- Add API key to use administration APIs via scripts without a cookie session

## 2.3.3

- Limit scheme available output
This is a security release, please upgrade your Glewlwyd version.
To mitigate server configuration leaks, I recommend the following actions:
  - If you use the TLS Certificate Scheme with [Allow to emit PKCS#12 certificates for the clients](https://github.com/babelouest/glewlwyd/blob/2.3/docs/CERTIFICATE.md#allow-to-emit-pkcs12-certificates-for-the-clients) enabled, please revoke the issuer certificate and use new ones
  - If you use the Webauthn Scheme, it's reommended to regenerate the [Random seed used to mitigate intrusion](https://github.com/babelouest/glewlwyd/blob/2.3/docs/WEBAUTHN.md#random-seed-used-to-mitigate-intrusion)
  - If you use the Oauth2 Scheme, please change the [clients secrets](https://github.com/babelouest/glewlwyd/blob/2.3/docs/OAUTH2_SCHEME.md#secret)
  - If yout use the Email code scheme and use a [SMTP password](https://github.com/babelouest/glewlwyd/blob/2.3/docs/EMAIL.md#smtp-password-if-required), please to change this password

## 2.3.2

- Allow to specify a public JWKS for OIDC plugin
- Fix official docker image builder
- Fix load module files on filesystems that don't fully support `readdir()`, closes #150
- Fix Small UI bugs
- Add manpage
- Add documentation on reverse proxy with examples for Apache and Nginx

## 2.3.1

- Upgrade Bootstrap to 4.5
- Replace Font-Awesome 5 with [Fork-Awesome](https://forkaweso.me/)
- Fix Mock scheme in profile page

## 2.3.0

The `"Saint-Jean-Baptiste Release"`

- Replace libjwt with Rhonabwy
- Allow messages encryption (incoming and outcoming)
- Allow OIDC plugin to use multiple signing or encryption keys via a JWKS
- Add support for CRYPT hash in ldap modules, closes #114
- Add [Session Management](https://openid.net/specs/openid-connect-session-1_0.html) for OIDC plugin
- Update access token claims to fit [JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens - draft 05](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-05)
- Add [JWT Response for OAuth Token Introspection](https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-08)
- Adapt client registration `redirect_uri` check to make Glewlwyd OIDC plugin conform to [OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252) specification
- Add [OAuth 2.0 Device Grant](https://tools.ietf.org/html/rfc8628)
- Add `id_token` in response type `password` when the scope `openid` is added
- Disable response type `password` by default for OIDC plugin config
- Scope `openid` is assumed to be always granted to clients for OIDC plugin
- Add `one-time-use` refresh token option
- Add [OAuth 2.0 Dynamic Client Registration Management Protocol](https://tools.ietf.org/html/rfc7592) for OIDC plugin
- Breaking change since 2.2: Client Registration input parameters are now conform to [OAuth 2.0 Dynamic Client Registration Protocol](https://tools.ietf.org/html/rfc7591)
- Add [OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://tools.ietf.org/html/rfc8705)
- Allow multi-languages e-mails in [e-mail scheme](docs/EMAIL.md) and [registration plugin](docs/REGISTER.md)
- Multiple bugfixes in UI and API

## 2.2.0

The `"Containment Release"`

- Add [OAuth2/OIDC authentication scheme](https://github.com/babelouest/glewlwyd/blob/master/docs/OAUTH2_SCHEME.md) to authenticate to Glewlwyd via an external provider
- Add [Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636) for OAuth2 and OIDC plugins
- Add [token introspection](https://tools.ietf.org/html/rfc7662) and [token revocation](https://tools.ietf.org/html/rfc7009) for OAuth2 and OIDC plugins
- Add [OpenID Connect Dynamic Registration](http://openid.net/specs/openid-connect-registration-1_0.html) for OIDC plugin
- Add [Form Post Response Mode](http://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html) for OIDC plugin
- Allow signed JWT requests using RSA or ECDSA algorithms in `/auth` or `/token` endpoints
- Catch close signal in another thread (Closes: #103)
- Fix bug to make Glewlwyd compatible with Apache Module [auth_openidc](https://github.com/zmartzone/mod_auth_openidc)

## 2.1.1

- Add claims `exp` and `nbf` in access tokens (see #99)
- Fix libjwt version required to help Debian Buster users

## 2.1.0

- Add custom css files so users can safely adapt css to their own identity
- Add packed format support in webauthn scheme
- improve webauthn scheme
- Fix i18n errors and typos
- Add Dutch translation in UI
- Add HTTP Basic Authentication Scheme
- Add `defaultScheme` option in UI config for passwordless authentication
- Add `bind_address` option in the config file
- Add possibility for users to remove their own account
- Add plugin `Register` to allow users to create new accounts
- Add HTTP Basic Auth scheme
- Multiple bugfixes and UI improvements
- Many thanks to all helpers who send feedback and bugfixes! Keep running :-)

## 2.0.0

- Fix UI bugs
- Fix Microsoft Edge bug
- Add possibility to build UI with Internet Explorer support
- Fix GCC9 warnings
- Add `autocomplete="off"` and `autofocus` properties in some input
- Clean UI code a lot by adding most libraries in `package.json` instead of static files in `webapp-src/js`
- Use vanilla `qrcode-generator` instead of `jquery.qrcode` because the last one embedded the first one, so it was overkill

## 2.0.0-rc2

- Allow to emit certificates for certificate scheme
- Bug fixes and improvements on certificate scheme
- Fix UI bugs
- Fix small backend bugs
- Add docker image
- Add Fail2ban script and config

## 2.0.0-rc1

- Improve documentation
- Improve OpenID Connect core plugin
- Add OpenID Connect discovery
- Add OpenID Connect core requests
- Add OpenID Connect address claims
- Add option max_age for session passwords
- Change OpenID Connect access token payload format to match id_token format
- Fix PostgreSQL database
- TOTP: forbid to use the same code twice
- Allow to use environment variables instead of or in addition to configuration file
- Add scheme TLS certificate
- Allow to use profile picture for users

## 2.0.0-b3

- Add OpenID Connect core plugin
- Fix lots of bugs and memory leaks
- Add more tests
- Change return type of all modules function `*_init()` to `json_t *` so the front-end will know about the error
- Improve documentation
- Can use environment variables as config parameters

## 2.0.0-b2

- Fix sample config with correct variable names, fix #57
- Fix webauthn bugs
- Improve documentation
- Fix build on supported platforms
- Fix #59 and add action reset to modules
- Make build and tests reproductive using Huddersfield

## 2.0.0-b1

- Massive rework for the better good
- Introduction of modules to handle different backend users, clients and authentication scheme
- Backends:
  - Database (user and client)
  - LDAP (user and client)
  - HTTP (user only)
- Schemes:
  - password
  - HOTP/TOTP
  - Code sent by e-mail
  - webauthn
- Introduction of plugins to handle authentication workflows
  - Legacy OAuth2 workflow
- User Interface revamped

## 1.4.9

- Small bugfixes
- Clean some memory leaks

## 1.4.8

- Add Travis CI script
- Fix http_auth backend

## 1.4.7

- Adapt Glewlwyd build to the new version of the underlying libraries: Orcania, Yder, Hoel, Ulfius (thanks ythogtha!)
- Improve doc about front-end pages, as mentioned in #46, and fix libjwt install doc

## 1.4.6

- Fix client confidential bug in code authorization flow, thanks to Bisco

## 1.4.5

- Add last glewlwyd_resource

## 1.4.4

- Add current token scope list in the API `/api/profile` when authenticated with the OAuth2 token
- Fix issue in client_check that made it not check properly if a client is authorized or not

## 1.4.3

- LDAP search error more verbose
- Fix LDAP search pagination

## 1.4.2

- Add option `auth_code_match_ip_address` to prevent glewlwyd to check the match of the IP address that requested a code and the IP address that requested the refresh token
- Fix bug with confidential clients that were not able to get refresh tokens
- Fix bug that made Glewlwyd crash when try to add users and ldap auth was disabled

## 1.4.1

- Update libraries dependency versions

## 1.4.0

- Add LDAP config properties search_scope, scope_property_user_match and scope_property_client_match
- Add Debian hardening patch on Makefile
- Add journald log mode

## 1.3.3

- Fix client_credentials bug
- Move documentation to /docs

## 1.3.2

- Add CMake install script

## 1.3.1

- Make glewlwyd admin application URL more changeable
- fix minor bugs and memory leaks

## 1.3.0

- Add http_auth backend #29

## 1.2.4

- Fix bug when scope doesn't exist and is requested

## 1.2.3

- fix a bug on the case letters for the username in the tokens

## 1.2.2

- Security improvement

## 1.2.1

- Improve install procedure for database init

## 1.2.0

- Add ECDSA signatures and now supports different signature size with the config parameter key_size.
If none is specified in the config file, default key_size value is 512

## 1.1.2

- Fix bug in update last_seen value for a refresh token

## 1.1.1

- Update API prefix to new default value

## 1.1.0

- Limit Ulfius functionalities with the one needed

## 1.0.1

- Improve documentation on Ulfius usage

## 1.0.0

- First stable release

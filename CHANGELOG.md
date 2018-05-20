# Glewlwyd Changelog

## 1.4.4

- Add current token scope list in the api `/api/profile` when authenticated with the OAuth2 token
- Fix issue in client_check that made it not check properly if a client is authorized or not

## 1.4.3

- LDAP search error more verbose
- Fix LDAP search pagination

## 1.4.2

- Add option `auth_code_match_ip_address` to prevent glewlwyd to check the match of the ip address that requested a code and the ip address that requested the refresh token
- Fix bug with confidentials clients that were not able to get refresh tokens
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

- Make glewlwyd admin application url more changeable
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

- Update api prefix to new default value

## 1.1.0

- Limit Ulfius functionalities with the one needed

## 1.0.1

- Improve documentation on ulfius usage

## 1.0.0

- First stable release

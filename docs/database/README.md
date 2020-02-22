# Database init scripts

The following scripts are available:

## Initialize Glewlwyd with the default settings and all tables for all schemes and modules

The initialized database will contain the user `admin` using the password `password`.

- [MariaDB/MySQL initialization](init.mariadb.sql)
- [Postgre SQL initialization](init.postgre.sql)
- [SQlite 3 initialization](init.sqlite3.sql)

## Upgrade Glewlwyd from 2.0.x to 2.1.x

### Install tables for Registration plugin

- [MariaDB/MySQL upgrade](../../src/plugin/register.mariadb.sql)
- [Postgre SQL upgrade](../../src/plugin/register.postgre.sql)
- [SQlite 3 upgrade](../../src/plugin/register.sqlite3.sql)

## Upgrade Glewlwyd from 2.1.x to 2.2.x

### Upgrade core tables structure

- [MariaDB/MySQL upgrade](upgrade-2.2.mariadb.sql)
- [Postgre SQL upgrade](upgrade-2.2.postgre.sql)
- [SQlite 3 upgrade](upgrade-2.2.sqlite3.sql)

### Install tables for OAuth2/OIDC scheme

- [MariaDB/MySQL upgrade](../../src/scheme/oauth2.mariadb.sql)
- [Postgre SQL upgrade](../../src/scheme/oauth2.postgre.sql)
- [SQlite 3 upgrade](../../src/scheme/oauth2.sqlite3.sql)

## Initialize only Glewlwyd core tables with no data

- [MariaDB/MySQL initialization](init-core.mariadb.sql)
- [Postgre SQL initialization](init-core.postgre.sql)
- [SQlite 3 initialization](init-core.sqlite3.sql)

## User backend database only

- [MariaDB/MySQL initialization](../../src/user/database.mariadb.sql)
- [Postgre SQL initialization](../../src/user/database.postgre.sql)
- [SQlite 3 initialization](../../src/user/database.sqlite3.sql)

## Client backend database only

- [MariaDB/MySQL initialization](../../src/client/database.mariadb.sql)
- [Postgre SQL initialization](../../src/client/database.postgre.sql)
- [SQlite 3 initialization](../../src/client/database.sqlite3.sql)

## E-mail code scheme only

- [MariaDB/MySQL initialization](../../src/scheme/email.mariadb.sql)
- [Postgre SQL initialization](../../src/scheme/email.postgre.sql)
- [SQlite 3 initialization](../../src/scheme/email.sqlite3.sql)

## HOTP/TOTP scheme only

- [MariaDB/MySQL initialization](../../src/scheme/otp.mariadb.sql)
- [Postgre SQL initialization](../../src/scheme/otp.postgre.sql)
- [SQlite 3 initialization](../../src/scheme/otp.sqlite3.sql)

## Webauthn scheme only

- [MariaDB/MySQL initialization](../../src/scheme/webauthn.mariadb.sql)
- [Postgre SQL initialization](../../src/scheme/webauthn.postgre.sql)
- [SQlite 3 initialization](../../src/scheme/webauthn.sqlite3.sql)

## TLS Certificate scheme only

- [MariaDB/MySQL initialization](../../src/scheme/certificate.mariadb.sql)
- [Postgre SQL initialization](../../src/scheme/certificate.postgre.sql)
- [SQlite 3 initialization](../../src/scheme/certificate.sqlite3.sql)

## OAuth2/OIDC scheme only

- [MariaDB/MySQL initialization](../../src/scheme/oauth2.mariadb.sql)
- [Postgre SQL initialization](../../src/scheme/oauth2.postgre.sql)
- [SQlite 3 initialization](../../src/scheme/oauth2.sqlite3.sql)

## OAuth2 plugin only

- [MariaDB/MySQL initialization](../../src/plugin/protocol_oauth2.mariadb.sql)
- [Postgre SQL initialization](../../src/plugin/protocol_oauth2.postgre.sql)
- [SQlite 3 initialization](../../src/plugin/protocol_oauth2.sqlite3.sql)

## OpenID Connect plugin only

- [MariaDB/MySQL initialization](../../src/plugin/protocol_oidc.mariadb.sql)
- [Postgre SQL initialization](../../src/plugin/protocol_oidc.postgre.sql)
- [SQlite 3 initialization](../../src/plugin/protocol_oidc.sqlite3.sql)

## Registration plugin only

- [MariaDB/MySQL initialization](../../src/plugin/register.mariadb.sql)
- [Postgre SQL initialization](../../src/plugin/register.postgre.sql)
- [SQlite 3 initialization](../../src/plugin/register.sqlite3.sql)

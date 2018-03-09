# Glewlwyd database scripts

This folder contains several scrpts to create or initialize the glewlwyd database.

If you use a MariaDB/Mysql database, you must have a valid access to the database first. The following script shows an example of how to create a database called `glewlwyd` with a user `glewlwyd` and a password `glewlwyd` that can be accessible from remote locations or localhost:

```sql
-- Create database and user
CREATE DATABASE `glewlwyd`;
GRANT ALL PRIVILEGES ON glewlwyd.* TO 'glewlwyd'@'%' identified BY 'glewlwyd';
GRANT ALL PRIVILEGES ON glewlwyd.* TO 'glewlwyd'@'localhost' identified BY 'glewlwyd';
FLUSH PRIVILEGES;
```

## init-[mariadb|sqlite3-md5|sqlite3-sha|sqlite3-sha256|sqlite3-sha512].sql

These files are databse creation and initialization scripts used for the type of database you need. The user 'admin' has the password 'password'. Once the database is set and your glewlwyd.conf file is valid, you can start the glewlwyd service and go to the webpage http[s]://localhost:4593/app/index.html.

### Secuity warning!

Those scripts create a valid database that allow to use glewlwyd but to avoid huge security issues, you must make 2 changes on your first connection:
- Change the admin password when you connect to the application
- Change the redirect_uri for the client `g_admin` with your real redirect_uri

## glewlwyd.init-db-only.[mariadb|sqlite3].sql

These files create an empty database with only authorization types and default scopes, but with no client or user.

## init-webapp-only.sql

This file creates the webapp client values to be able to connect to the admin page

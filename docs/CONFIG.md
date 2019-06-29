# Configuration

## Glewlwyd manager

Glewlwyd comes with a small web application to manage profile, users, clients, scopes, modules, schemes and plugins.

The front-end management application is a tiny single page app (SPA) written in ReactJS/JQuery, responsive as much as I can, not the best design in the world, but useful anyway.

### Configuration

The config file `glewlwyd.conf` contains the variable `static_files_path`, it is the path to the front-end application. Set it to the location of your webapp folder before running glewlwyd, e.g. `"/usr/share/glewlwyd/webapp"`.

### Scope

To connect to the management application, you must use a user that have `g_admin` scope.

## Glewlwyd user profile

![User Profile](docs/screenshots/profile.png)
![Update password](docs/screenshots/profile password.png)

Glewlwyd comes with a profile manager for the connected users, where they will be able to change their display name or their password (if possible), check the access granted on their name and the scopes they are allowed to use, manage and register allowed authentication schemes, and revoke sessions or refresh tokens.

## Client configuration

### Client settings in Glewlwyd

The client application that will use Glewlwyd as SSO instance will require some configuration too.

![Client settings](docs/screenshots/client-edit.png)

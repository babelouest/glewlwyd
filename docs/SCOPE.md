# Glewlwyd Scopes Management

![scope-add](screenshots/scope-add.png)

A scope in Glewlwyd is an access level that the user, if it has the scope available, can or not grant access to clients.

From the administrator point-of-view, the scope can require more or less authenticator factors. The first authentication factor is the password, which is required by default when you create a new scope. You can add n-factor authentication to this scope and setup password session max age to enhance security access.

Here is the documentation of the options available when you create or edit a scope:

## Name

This option is mandatory, it's the scope unique name and identifier

## Display Name

This option is optional, it's the scope long name that will be displayed to users.

## Description

This option is optional, it's a short description of the scope.

## Password checkbox

Force authentication with the password to allow this scope for the user on the current session.

## Password session duration (0: unlimited)

If password is required, set a maximum age for the password in the current session. Setting this option to 0 means unlimited session.

## Additional authentication schemes

In this section, you can add one or more authentication schemes to the scope. You can gather authentication schemes in groups to allow multiple authentication factor, and you can have multiple groups to force more than one additional authentication factor.

The authentication group model can be represented as the following schema:

Scope 1: password `AND` (mail `OR` webauthn) `AND` (TOTP `OR` certificate)

Scope 2: (mail `OR` certificate `OR` webauthn)

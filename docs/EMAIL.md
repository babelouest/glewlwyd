# Glewlwyd Email code Schema Documentation

[![License: CC BY-SA 4.0](https://licensebuttons.net/l/by-sa/4.0/80x15.png)](https://creativecommons.org/licenses/by-sa/4.0/)

![scheme-email](screenshots/scheme-email.png)

The Email code Schema implements authentification based on random One-Time-Password generated on demand.

## Installation

In the administration page, go to `Parameters/Authentication schemes` and add a new scheme by clicking on the `+` button. In the modal, enter a name and a display name (the name must be unique among all authentication scheme instances), and a scheme session expiration in seconds.
Select the type `Email code` in the Type dropdown button.

Below is the definition of all parameters.

### Name

Name (identifier) of the scheme, must be unique among all the scheme instances, even of a different type.

### Display name

Name of the instance displayed to the user.

### Expiration (seconds)

Number of seconds to expire a valid session.

### Max use per session (0: unlimited)

Maximum number of times a valid authentification with this scheme is possible. This is an additional parameter used to enforce the security of the session and forbid to reuse this session for other authentications.

### Allow users to register

If this option is unchecked, only administrator can register this scheme for every user via the administration page.

### Code length

Length of the code that must be sent by the user. Must be a positive non null integer.

### Code duration (in seconds)

Duration of the code validity in seconds. This option must be short enough to limitate brute force attacks, but long enough to give time for the user to receive the message, open the message, then type the password in Glewlwyd authentification page.

### SMTP Server

Address of the SMTP server that will relay the messages to the users, mandatory.

### Port SMTP (0: System default)

TCP port the SMTP server is listening to. Must be between 0 and 65535. If 0 is set, Glewlwyd will use the system default port for SMTP, usually 25 or 587, mandatory.

### Use a TLS connection

Check this option if the SMTP server requires TLS to connect.

### Check server certificate

Check this option if you want Glewlwyd to check the SMTP server certificate before relaying the e-mail. This is highly recommended if TLS connection is checked, useless otherwise.

### SMTP username (if required)

username used to authenticate to the SMTP server if required by the SMTP server, optional.

### SMTP password (if required)

password used to authenticate to the SMTP server if required by the SMTP server, optional.

### E-mail sender address

Address used as sender in the e-mails, required.

### Content-Type

Content-Type for the e-mails, default is plain text but you can set an HTML body if youo need to.

### User lang property

User property which will contain the default lang value used for the e-mail templates. The lang value must be an exact match of the lang template. If the user lang doens't exist in the templates or if the user has no lang property, the e-mail template will use the default language.

### Lang

Dropdown value to select, add or remove lang templates for the e-mails.

### Default lang

Checkbox to specify what lang is the default language. In case the user has no language value or its language value doesn't exist in the templates.

### E-mail subject

Subject used on the e-mails for the current lang, required.

### E-mail body, the pattern {CODE} will be replaced by the code.

The pattern for the body on the e-mails for the current lang, You must use at least once the string `{CODE}` in the pattern to be replaced by the code.

Example, by using the following e-mail pattern:

```
Glewlwyd authentification code: {CODE}
```

Users will receive the following message:

```
Glewlwyd authentification code: 123456
```

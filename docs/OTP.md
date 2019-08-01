# Glewlwyd OTP Schema documentation

The OTP Schema implements authentification based on One-Time-Password using OATH standard defined in [HOTP](https://tools.ietf.org/html/rfc4226) and [TOTP](https://tools.ietf.org/html/rfc6238).

## Installation

In the administration page, go to `Parameters/Authentication schemes` and add a new scheme by clicking on the `+` button. In the modal, enter a name and a display name (the name must be unique among all authentication scheme instances), and a scheme session expiration in seconds.
Select the type `HOTP/TOTP` in the Type dropdown button.

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

### Issuer

Address of the issuer of the OTP settings, i.e. the address of the webservice hosting Glewlwyd.

### Secret minimum size

Size of the secret shared between the user and the server to authenticate the user. Minimum 16 bytes.

### Code length

Length of the code that must be sent by the user, must be between 6 and 10, 6 or 8 is recommended.

### HOTP

Allow users to register an HOTP code.

### HOTP window

Window validity of the HOTP code.

### TOTP

Allow users to register an TOTP code.

### TOTP window

Window validity of the TOTP code in seconds.

### Start offset

Start offset of the TOTP code related to Unix EPOCH time.

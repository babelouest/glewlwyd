# Fail2ban filter example

You can add specific filter for fail2ban to ban potential attackers.

The `glewlwyd.conf` file is available in [fail2ban/glewlwyd.conf](fail2ban/glewlwyd.conf). It will ban the IP addresses using the following rules:
- `Authorization invalid` - on a failed auth
- `Code invalid` - on a invalid code in OAuth2 or OIDC
- `Token invalid` - on a invalid code in OAuth2 or OIDC
- `Scheme email - code sent` - when an OTP code is sent via e-mail, to avoid spamming users

The `glewlwyd.conf` has the following content:

```config
# Fail2Ban filter for Glewlwyd
#
# Author: Nicolas Mora
#

[Definition]

failregex = ^.* - Glewlwyd WARNING: Security - Authorization invalid for username .* at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Code invalid at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Token invalid at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Scheme email - code sent for username .* at IP Address <HOST>
ignoreregex =
```

You must place the file `glewlwyd.conf` under the fail2ban `filter.d` directory (On Debian-based distrib it's located in `/etc/fail2ban/filter.d/`).

Then, you must update your `jail.local` file (On Debian-based distrib it's located in `/etc/fail2ban/jail.local`) by adding the following paragraph:

```config
[glewlwyd]
enabled  = true
filter   = glewlwyd
logpath  = /var/log/glewlwyd.log
port     = http,https
```

Check out [Fail2ban](https://www.fail2ban.org/) documentation for more information.

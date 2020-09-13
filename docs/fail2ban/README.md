# Fail2ban filter example

You can add specific filter for fail2ban to ban potential attackers.

The `glewlwyd.conf` file is available in [fail2ban/glewlwyd.conf](fail2ban/glewlwyd.conf). It will ban the IP addresses using the following rules:
- `Authorization invalid` - on a failed auth
- `Code invalid` - on a invalid code in OAuth2 or OIDC
- `Token invalid` - on a invalid code in OAuth2 or OIDC
- `Scheme email - code sent` - when an OTP code is sent via e-mail, to avoid spamming users

The `glewlwyd.conf` has the following content if you log to a user-defined log file:

```config
# Fail2Ban filter for Glewlwyd
#
# Author: Nicolas Mora
#

[Definition]

failregex = ^.* - Glewlwyd WARNING: Security - Authorization invalid for username .* at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Authorization invalid for client_id .* at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Code invalid at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Token invalid at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Scheme email - code sent for username .* at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Register new user - code sent to email .* at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Verify e-mail - code invalid at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Update e-mail - token sent to email .* at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Update e-mail - token invalid at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Reset credentials - token invalid at IP Address <HOST>
            ^.* - Glewlwyd WARNING: Security - Reset credentials - code invalid at IP Address <HOST>
ignoreregex =
```

The `glewlwyd.conf` has the following content if you log to syslog:

```config
# Fail2Ban filter for Glewlwyd
#
#
#
[INCLUDES]
#
# load the 'common.conf' list of fail2ban upstream maintained prefixes
#
before = common.conf

[Definition]
#
# declare the daemon name so common.conf variables will match
#
_daemon = Glewlwyd

failregex = ^.* %(__prefix_line)sSecurity - Authorization invalid for username .* at IP Address <HOST>
            ^.* %(__prefix_line)sSecurity - Authorization invalid for client_id .* at IP Address <HOST>
            ^.* %(__prefix_line)sSecurity - Code invalid at IP Address <HOST>
            ^.* %(__prefix_line)sSecurity - Token invalid at IP Address <HOST>
            ^.* %(__prefix_line)sSecurity - Scheme email - code sent for username .* at IP Address <HOST>
            ^.* %(__prefix_line)sSecurity - Register new user - code sent to email .* at IP Address <HOST>
            ^.* %(__prefix_line)sSecurity - Verify e-mail - code invalid at IP Address <HOST>
            ^.* %(__prefix_line)sSecurity - Update e-mail - token sent to email .* at IP Address <HOST>
            ^.* %(__prefix_line)sSecurity - Update e-mail - token invalid at IP Address <HOST>
            ^.* %(__prefix_line)sSecurity - Reset credentials - token invalid at IP Address <HOST>
            ^.* %(__prefix_line)sSecurity - Reset credentials - code invalid at IP Address <HOST>
ignoreregex =
```

You must place the file `glewlwyd.conf` under the fail2ban `filter.d` directory (On Debian-based distrib it's located in `/etc/fail2ban/filter.d/`).

Then, you must update your `jail.local` file (On Debian-based distrib it's located in `/etc/fail2ban/jail.local`) by adding the following paragraph if you use a user-defined log:

```config
[glewlwyd]
enabled  = true
filter   = glewlwyd-log
logpath  = /var/log/glewlwyd.log
port     = http,https
```

...or change the filter name to glewlwyd-syslog if you use the syslog filter:

```config
[glewlwyd]
enabled  = true
filter   = glewlwyd-syslog
logpath  = /var/log/glewlwyd.log
port     = http,https
```

Check out [Fail2ban](https://www.fail2ban.org/) documentation for more information.

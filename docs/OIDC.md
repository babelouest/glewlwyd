# Glewlwyd OpenID Connect Plugin documentation

This plugin is based on the [OpenID Connect Core 1.0 specification](https://openid.net/specs/openid-connect-core-1_0.html) and allows Glewlwyd to act as an OpenID Provider (OP).

## Functionalities summary

The following OpenID Connect Core functionalities are currently supported:

- [Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
- [Implicit flow](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth)
- [Hybrid flow](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth)
- [UserInfo Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)

The following OpenID Connect Core functionalities are not supported yet:

- [Address Claims](https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim)
- [Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
- [Requesting Claims using the "claims" Request Parameter](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)
- [id_token_hint](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) in the authentication request parameters
- [Passing Request Parameters as JWTs](https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests)
- [Self-Issued OpenID Provider](https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued)
- [id_token encryption](https://openid.net/specs/openid-connect-core-1_0.html#Encryption)
- [Client authentication](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) other than HTTP Basic auth

## Access token format

As a heir of [Glewlwyd OAuth2 plugin](OAUTH2.md), Glewlwyd OpenID Connect plugin uses JWTs as access tokens. Therefore, the access token can be used by the client or the third party web service to identify the user and the scopes available with this access token.

An access token payload has the following JSON format:

```Javascript
{
  "username": "user1", // Username that was provided this access_token
  "salt": "abcdxyz1234", // Random string to avoid collisions
  "type": "access_token", // Hardcoded
  "iat": 1466556840, // Issued at time in Epoch Unix format
  "expires_in": 3600, // Number of seconds of validity for this token
  "scope":["scope1","g_profile"] // scopes granted to this access token
}
```

## Installation

In the administration page, go to `Parameters/Plugins` and add a new plugin by clicking on the `+` button. In the modal, enter a name and a display name (the name must be unique among all user backend instances).
Select the type `Glewlwyd OpenID Connect Plugin` in the Type dropdown button.

Below is the definition of all parameters.

### Name

Name (identifier) of the plugin instance, must be unique among all the plugin instances, even of a different type.

### Display name

Name of the instance displayed to the user.

### Issuer

Issuer that will be added in all ID Tokens, must correspond to your Glewlwyd instance URL.

### JWT Type

Algorithm used to sign access tokens and ID Tokens.

The algorithm supported are `RSA` and `ECDSA` using a private and a public key, and `SHA` using a shared secret.

### Key size

Size of the key to sign the tokens. The sizes supported are 256 bits, 384 bits or 512 bits.

### Key

Private key file used to sign if the selected algorithm is `RSA` or `ECDSA`. Must be an X509 PEM file.
Shared secret if the selected algorithm is `SHA`.

### Public certificate

Public certificate file used to validate access tokens if the selected algorithm is `RSA` or `ECDSA`. Must be an X509 PEM file.

### Access token duration (seconds)

Duration of each access tokens. Default value is 3600 (1 hour).

### Refresh token duration (seconds)

Duration of validity of each refresh tokens. Default value is 1209600 (14 days).

### Code duration (seconds)

Duration of validity of each code sent to the client befire requesting a refresh token. Default value is 600 (10 minutes).

### Refresh token rolling

If this option is checked, every time an access token is requested using a refresh token, the refresh token issued at time will be reset to the current time. This option allows infinite validity for the refresh tokens if it's not manually disabled, but if a refresh token isn't used for more of the value `Refresh token duration`, it will be disabled.

### Allow non OIDC but valid OAuth2 requests

If this option is checked, the plugin instance will allow requests that are not allowed in the OIDC standard but valid in the OAuth2 standard, such as response_type: `token` (alone), `password` or `client_credential`. In those cases, the request will be trated as a normal OAuth2 but the response will not have an ID Token.

### Authentication type code enabled

Enable response type `code`.

### Authentication type token enabled

Enable response type `token`.

### Authentication type ID Token enabled

This option is enabled and can't be disabled.

### Authentication type password enabled

Enable response type `password`.

### Authentication type client enabled

Enable response type `client_credential`.

### Authentication type refresh enabled

Enable response type `refresh_token`.

### Specific scope parameters

This section allows to put specific settings for an scope that will override the plugin settings.

The settings that you can override are `Refresh token duration` and/or `Rolling refresh`.

Please note that a specific scope parameter has a higher priority than the plugin settings, and if have multiple scopes in a request that have specific settings, the settings will follow the following algorithm:
- Refresh token duration: The duration provided will be the lowest duration among all the specific scope parameters.
- Roling refresh: The value `No`has higher priority, therefore rolling refresh provided will be `No` if one scope has the value `No`, `Yes` otherwise

### Additional token values

This section allows to add specific values to the access_tokens that will be taken from the user property values.

You can add as many additional values as you want. If the property isn't present in the user data, it will be ignored. If the value is mutiple, all values will be present, separated by a comma `,`.

### Additional parameters in the ID Token or the /userinfo endpoint

This section allows to add specific claims in ID Tokens or userinfo results.

If you specify a type `number`, the value will be converted from a string to an integer.

If the conversion fails, the value will be ignored. If you specify a type `boolean`, you must specify the values for `true` and `false`. If the value doesn't match, it will be ignored.

If you check the option `Mandatory`, the claim will be added in all ID Tokens or userinfo calls, even if the claim isn't requested by the user.

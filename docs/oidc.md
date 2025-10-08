# OIDC Module

OIDC module adds support for the OpenID Provider role from the OpenID Connect protocol
through a SimpleSAMLphp module installable via Composer. It is based on
[OAuth2 Server from the PHP League](https://oauth2.thephpleague.com/).

Currently supported flows are:
* Authorization Code flow, with PKCE support (response_type 'code')
* Implicit flow (response_type 'id_token token' or 'id_token')
* Refresh Token flow

# TOC
* [Installation](installation.md)

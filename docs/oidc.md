# OIDC Module

This module adds support for the OpenID Provider (OP) role from the
OpenID Connect protocol to SimpleSAMLphp. It is installable via Composer
and is based on the
[OAuth2 Server from the PHP League](https://oauth2.thephpleague.com/).

Supported flows:
- Authorization Code, with PKCE (response_type: `code`)
- Implicit (response_type: `id_token token` or `id_token`)
- Refresh Token

![Main screen capture](oidc.png)

## Note on OpenID Federation (OIDFed)

OpenID Federation support is in draft, as is the
[specification](https://openid.net/specs/openid-federation-1_0). You can
expect breaking changes in future releases related to OIDFed
capabilities. OIDFed can be enabled or disabled in the module
configuration.

Currently supported OIDFed features:
- Automatic client registration using a Request Object (by value)
- Federation participation limiting based on Trust Marks
- Endpoint for issuing a configuration entity statement (about itself)
- Fetch endpoint for issuing statements about subordinates (clients)
- Subordinate listing endpoint

OIDFed is implemented using the
[SimpleSAMLphp OpenID library](https://github.com/simplesamlphp/openid).

## Version compatibility

Minor versions listed show which SimpleSAMLphp versions were used during
module development. SimpleSAMLphp follows semantic versioning for its
API since v2.0. For example, v5.* of the OIDC module should work with
any v2.* of SimpleSAMLphp. PHP version requirements may differ.

- OIDC v6.*  → SimpleSAMLphp v2.3.*, v2.4.*   → PHP >= 8.2 (recommended)
- OIDC v5.*  → SimpleSAMLphp v2.1.*           → PHP >= 8.1
- OIDC v4.*  → SimpleSAMLphp v2.0.*           → PHP >= 8.0
- OIDC v3.*  → SimpleSAMLphp v2.0.*           → PHP >= 7.4
- OIDC v2.*  → SimpleSAMLphp v1.19.*          → PHP >= 7.4

Upgrading? See the [upgrade guide](upgrade.md).

## Documentation

- Getting started: [Installation](installation.md)
- Configure and operate: [Configuration](configuration.md)
- Manage clients and UI: see [Configuration](configuration.md#relying-party-rp-administration)
- Endpoints and discovery: see
  [Configuration](configuration.md#endpoint-locations-and-well-known-urls)
- Running with containers: [Using Docker](docker.md)
- Conformance tests: [OpenID Conformance](conformance.md)
- Upgrading between versions: [Upgrade guide](upgrade.md)
- Common questions: [FAQ](faq.md)

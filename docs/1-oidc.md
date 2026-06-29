# OIDC Module

This module adds support for the OpenID Provider (OP) role from the
OpenID Connect protocol to SimpleSAMLphp. It is installable via Composer
and is based on the
[OAuth2 Server from the PHP League](https://oauth2.thephpleague.com/).

Supported flows:

- Authorization Code, with PKCE (response_type: `code`)
- Implicit (response_type: `id_token token` or `id_token`)
- Refresh Token

Authorization request parameters can be sent as plain parameters, by value as a
Request Object (`request`, OpenID Connect Core / JAR), or by reference
(`request_uri`) — either via Pushed Authorization Requests (PAR, RFC 9126) or a
remote `https://` Request Object. See
[Configuration](3-oidc-configuration.md#pushed-authorization-requests-par-and-request-objects)
for details.

## Supported specifications

This OP implements (or, where noted, partially implements) the following
specifications:

OpenID Connect:

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
  — Authorization Code and Implicit flows, ID Token, UserInfo, and the `request`
  object (passed by value and by reference)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
  — `/.well-known/openid-configuration`
- [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
  — the Client Registration Endpoint (`registration_endpoint`); disabled by
  default. See the [DCR note](#note-on-dynamic-client-registration-dcr) below
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
  — supported response modes are `query`, `fragment`, and `form_post`

OAuth 2.0:

- [The OAuth 2.0 Authorization Framework (RFC 6749)](https://www.rfc-editor.org/rfc/rfc6749)
  and [Bearer Token Usage (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750)
- [Proof Key for Code Exchange, PKCE (RFC 7636)](https://www.rfc-editor.org/rfc/rfc7636)
- [OAuth 2.0 Authorization Server Metadata (RFC 8414)](https://www.rfc-editor.org/rfc/rfc8414)
  — `/.well-known/oauth-authorization-server`
- [JWT Profile for Client Authentication (RFC 7523)](https://www.rfc-editor.org/rfc/rfc7523)
  — `private_key_jwt` at the token and PAR endpoints (token endpoint also
  supports `client_secret_basic` and `client_secret_post`)
- [OAuth 2.0 Token Introspection (RFC 7662)](https://www.rfc-editor.org/rfc/rfc7662)
  — optional endpoint
- [JWT-Secured Authorization Request, JAR (RFC 9101)](https://www.rfc-editor.org/rfc/rfc9101)
  — `request` and `request_uri`
- [OAuth 2.0 Pushed Authorization Requests, PAR (RFC 9126)](https://www.rfc-editor.org/rfc/rfc9126)
- [OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)](https://www.rfc-editor.org/rfc/rfc7591)
  and [OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592)](https://www.rfc-editor.org/rfc/rfc7592)
  — client register / read / update / delete at the `registration_endpoint`;
  disabled by default. See the [DCR note](#note-on-dynamic-client-registration-dcr) below

Drafts / experimental (see the notes below for scope and caveats):

- OpenID Federation — automatic client registration and related features
  (draft; breaking changes expected)
- OpenID for Verifiable Credential Issuance, OpenID4VCI (draft 15; experimental,
  not for production)

## Note on Dynamic Client Registration (DCR)

The OP can let clients register themselves at the Client Registration Endpoint
(`registration_endpoint`, served at `<basepath>/module.php/oidc/register`),
implementing OpenID Connect Dynamic Client Registration 1.0 / RFC 7591 (create,
read) and RFC 7592 (update, delete via the Client Configuration Endpoint,
authenticated with the Registration Access Token issued at registration).

DCR is **disabled by default**. When disabled, the registration endpoint returns
`404` and is not advertised in discovery. When enabled, registration can be open
or gated by an Initial Access Token, and impersonation protection
(`logo_uri`/`policy_uri`/`tos_uri` host matching) is on by default.

Most standard client metadata is supported. Metadata for features this OP does
not implement is **rejected** with `invalid_client_metadata` rather than silently
ignored — namely `subject_type` other than `public`, `sector_identifier_uri`,
signed/encrypted UserInfo, ID Token / Request Object encryption, and front-channel
logout. The full per-field policy (honored / validated / rejected) is documented in
[DCR client metadata support](9-oidc-dcr-client-metadata.md). See the
[upgrade guide](6-oidc-upgrade.md#version-6-to-7) for the configuration options,
the client properties involved, and guidance for existing clients.

## Note on OpenID Federation (OIDFed)

OpenID Federation support is in draft phase. You can
expect breaking changes in future releases related to OIDFed
capabilities. OIDFed can be enabled or disabled in the module
configuration.

Currently supported OIDFed features:

- Automatic client registration using a Request Object
- Federation participation limiting based on Trust Marks
- Endpoint for issuing a configuration entity statement (about itself)
- Fetch endpoint for issuing statements about subordinates (clients)
- Subordinate listing endpoint

OIDFed is implemented using the
[SimpleSAMLphp OpenID library](https://github.com/simplesamlphp/openid).

## Note on OpenID for Verifiable Credential Issuance (OpenID4VCI) support

OpenID4VCI support was done as per draft 15 of the specification and is in the
experimental stage. You should NOT use it in production environments.

Currently implemented OpenID4VCI features:

- Implemented Endpoints
  - Credential Issuer Metadata | `.well-known/openid-credential-issuer` -
  Advertises supported credentials, algorithms, and endpoints.
  - Credential Endpoint | `/vci/credential`- Handles credential requests with
  proof of possession.
  - Nonce Endpoint - `/vci/nonce` - Provides nonces (`c_nonce`).
  - Credential Offer (API) | `/api/vci/offer` - Allows triggering credential
  offers via administrative API.
  - JSON-LD Context | `/vci/context/{id}` - Serves custom JSON-LD contexts for
  `vc+sd-jwt` credentials.
- Supported Flows & Grant Types
  - Authorization Code Flow: Fully supported
  - Pre-Authorized Code Flow: Fully supported
  - Authorization Details: Support for `openid_credential` type in authorization
  and token requests.
- Supported Credential Formats
  - JWT VC JSON (`jwt_vc_json`): W3C VCDM v1.1 Verifiable Credentials encoded as
  JWT.
  - Selective Disclosure JWT (`vc+sd-jwt`): W3C VCDM 2.0 based Selective
  Disclosure JWT.
  - Digital Credentials SD-JWT (`dc+sd-jwt`): IETF Draft 14+ Selective
  Disclosure JWT.
Proof of Possession & Binding
  - Proof Type: `jwt` (JSON Web Token proofs).
  - Cryptographic Binding Methods:
    - `did:key`: Supported for proof validation and subject binding.
    - `did:jwk`: Supported for proof validation and subject binding.
  - Nonce Validation for mandatory `c_nonce` validation in proofs.
- JSON-LD Support: Ability to host and reference custom JSON-LD contexts for
enhanced semantic interoperability
- API for credential offer fetching

OpenID4VCI is also implemented using the
[SimpleSAMLphp OpenID library](https://github.com/simplesamlphp/openid).

## Conformance testing

On every build, CI runs the following OpenID Foundation certification test
plans against the module (using the OpenID conformance suite). See
[OpenID Conformance](5-oidc-conformance.md) for how to run them yourself:

- OpenID Connect Core: Basic OP (`oidcc-basic-certification-test-plan`)
- OpenID Connect Core: Implicit OP (`oidcc-implicit-certification-test-plan`)
- OpenID Connect Core: Form Post Basic OP
  (`oidcc-formpost-basic-certification-test-plan`)
- OpenID Connect Core: Form Post Implicit OP
  (`oidcc-formpost-implicit-certification-test-plan`)
- OpenID Connect RP-Initiated Logout
  (`oidcc-rp-initiated-logout-certification-test-plan`)
- OpenID Connect Back-Channel Logout
  (`oidcc-backchannel-rp-initiated-logout-certification-test-plan`)
- OpenID Connect Core: Dynamic OP
  (`oidcc-dynamic-certification-test-plan`) — exercises Dynamic Client
  Registration. A few tests in this plan cover OP behaviours that are not DCR and
  are not (yet) supported; they are tracked as expected failures. See
  [OpenID Conformance](5-oidc-conformance.md) for details.

Some specifications are not covered by these OpenID Connect certification
profiles. In particular, PAR (RFC 9126) and the `request` / `request_uri`
handling are validated separately: their MUST-level requirements are tracked
and mapped to unit tests in `conformance-tests/rfc9126-par-compliance.md`.

## Version compatibility

Minor versions listed show which SimpleSAMLphp versions were used during
module development. SimpleSAMLphp follows semantic versioning for its
API since v2.0. PHP version requirements may differ.

| OIDC module | Tested SimpleSAMLphp |  PHP   |
|:------------|:---------------------|:------:|
| v6.4.\*     | v2.5.\*              | \>=8.3 |
| v6.3.\*     | v2.3.\*, v2.4.\*     | \>=8.2 |
| v5.\*       | v2.1.\*              | \>=8.1 |
| v4.\*       | v2.0.\*              | \>=8.0 |
| v3.\*       | v2.0.\*              | \>=7.4 |
| v2.\*       | v1.19.\*             | \>=7.4 |

Upgrading? See the [upgrade guide](6-oidc-upgrade.md).

## Documentation

- Getting started: [Installation](2-oidc-installation.md)
- Configure and operate: [Configuration](3-oidc-configuration.md)
- Manage clients and UI: see [Configuration](3-oidc-configuration.md#relying-party-rp-administration)
- Endpoints and discovery: see
  [Configuration](3-oidc-configuration.md#endpoint-locations-and-well-known-urls)
- Running with containers: [Using Docker](4-oidc-docker.md)
- Conformance tests: [OpenID Conformance](5-oidc-conformance.md)
- Dynamic Client Registration metadata support:
  [DCR client metadata](9-oidc-dcr-client-metadata.md)
- Upgrading between versions: [Upgrade guide](6-oidc-upgrade.md)
- Common questions: [FAQ](7-oidc-faq.md)
- API documentation: [API](8-api.md)

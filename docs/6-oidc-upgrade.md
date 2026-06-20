# OIDC Module - Upgrade guide

This is an upgrade guide from versions 1 → 7. Review the changes and
apply those relevant to your deployment.

In general, when upgrading any of the SimpleSAMLphp modules or the
SimpleSAMLphp instance itself, you should clear the SimpleSAMLphp
cache after the upgrade. In newer versions of SimpleSAMLphp, the
following command is available to do that:

```shell
composer clear-symfony-cache
```

## Version 6 to 7

As the database schema has been updated, you will have to run the DB migrations
to bring your local database schema up to date.

New features:

- Instance can now be configured to support multiple algorithms and signature
keys for protocol (Connect), Federation, and VCI purposes. This was introduced
to support signature algorithm negotiation with the clients.
- Clients can now be configured with new properties:
  - ID Token Signing Algorithm (`id_token_signed_response_alg`)
- Optional OAuth2 Token Introspection endpoint, as per RFC7662. Check the API
documentation for more details.
- Initial support for OpenID for Verifiable Credential Issuance
(OpenID4VCI). Note that the implementation is experimental. You should not use
it in production.
- Support for Pushed Authorization Requests (PAR) as per RFC 9126. A new PAR
endpoint (`pushed_authorization_request_endpoint`, served at
`<basepath>/module.php/oidc/par`) lets clients push authorization request
parameters in a back-channel `POST` and receive a one-time, short-lived
`request_uri` (`urn:ietf:params:oauth:request_uri:...`) to use at the
authorization endpoint. It can be required globally or per client.
- Support for passing a Request Object by reference using the `request_uri`
parameter (in addition to the existing by-value `request` support), covering
both JWT-Secured Authorization Request (JAR, RFC 9101) by reference and OpenID
Federation by reference. Remote `https://` Request Objects are fetched by the
OP, subject to client registration / federation allowlisting. The OP now
differentiates the Request Object flavor (OpenID Connect Core, JAR, or OpenID
Federation) and applies the matching signing rules; when present, the `aud` and
`iss` claims of OpenID Connect Core and JAR Request Objects are validated.
- Clients can now be configured with new properties related to the above:
  - Require Pushed Authorization Requests (`require_pushed_authorization_requests`)
  - Require Signed Request Object (`require_signed_request_object`)
  - Registered Request URIs (`request_uris`)
See the [configuration guide](3-oidc-configuration.md#pushed-authorization-requests-par-and-request-objects)
for details.
- Support for the OAuth 2.0 Form Post Response Mode (`response_mode=form_post`).
The OP now supports three response modes - `query`, `fragment`, and
`form_post`. With `form_post`, the authorization response parameters are
returned to the client via an auto-submitting HTML form (`POST` to the redirect
URI) instead of in the URL query string or fragment. When `response_mode` is
not provided, the spec default is used (`fragment` for responses containing a
token, otherwise `query`). The supported response modes are now also advertised
in the OP discovery metadata via the `response_modes_supported` claim.
- Clients can now be configured with a new property related to the above:
  - Allowed Response Modes (`allowed_response_modes`) - a per-client allowlist
  of permitted response modes. When not set, all supported response modes
  (`query`, `fragment`, `form_post`) are allowed, so existing clients are
  unaffected. It can be narrowed, for example to `form_post` only, to protect
  against browser-swapping attacks (if supported by the client).
- Authentication Processing Filters can now be configured per client (Relying
Party), in addition to the global filters defined under `authproc.oidc`. This
mimics defining authproc filters in SAML Service Provider metadata. During
authentication the global (IdP-side) and per-client (SP-side) filters are merged
by priority. The filters are stored together with the client (inside its extra
metadata) and are managed from the client administration UI as a JSON object,
using the same structure as the global filters. For security reasons, per-client
filters can only be set by an administrator (via the admin UI / API) and are
deliberately never accepted from client-supplied dynamic / OpenID Federation
registration metadata (a filter names a PHP class executed on the OP, so
honoring it from registration would be a remote code execution vector).
  - Clients can now be configured with a new property related to the above:
    - Authentication Processing Filters (`authproc`)
- The encryption key (used to encrypt / decrypt artifacts like authorization
codes and refresh tokens) can now optionally be set to a strong, pre-generated
`\Defuse\Crypto\Key`, instead of always deriving it from the SimpleSAMLphp
secret salt. By default, the behavior is unchanged: the secret
salt is used as a string password, from which the underlying League OAuth2
library derives the key using a slow key-stretching function (key derivation) on
every operation. If you instead provide a `\Defuse\Crypto\Key` (serialized to its
ASCII-safe string form) via the new option below, that strong key is used
directly, skipping the slow derivation and improving encryption / decryption
performance. Note that changing the encryption key (including switching from the
secret salt to a Key, or rotating a Key) invalidates all outstanding encrypted
artifacts (existing authorization codes, refresh tokens, and PAR request URIs
will be rejected), so only set or change it during a planned maintenance window.
- The user identifier attribute option
(`ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE`, `useridattr`) can now be
configured either as a single attribute name (string, as before) or as an array
of prioritized attribute names. This is useful in scenarios with multiple
heterogeneous IdPs (for example, eduGAIN inter-federation), where not every IdP
is able (or willing) to release the same identifier attribute. When an array is
given, the attributes are consulted in priority order and the first one actually
present in the released attributes is used, both as the internal user identifier
and as the default source for the `sub` claim. The single-string form continues
to work unchanged, so existing configurations are unaffected.

New configuration options:

- `ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS` - (required) enables
defining multiple protocol (Connect) related signing algorithms and key pairs.
- `ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS` - (required if
federation capabilities are enabled) enables defining multiple key pairs for
Federation purposes like signing Entity Statements, publishing new key for
key roll-ower scenarios, etc.
- `ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS` - (required if VCI
capabilities are enabled) enables defining multiple key pairs for
VCI purposes like signing Verifiable Credentials, publishing new key for
key roll-ower scenarios, etc.
- `ModuleConfig::OPTION_TIMESTAMP_VALIDATION_LEEWAY` - optional, used for
setting allowed time tolerance for timestamp validation in artifacts like JWSs.
multiple Federation-related signing algorithms and key pairs.
- `ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED` -
optional, enables the OAuth2 token introspection endpoint as per RFC7662.
- `ModuleConfig::OPTION_PAR_REQUEST_URI_TTL` - optional, lifetime of a PAR
`request_uri` (default `PT10M`).
- `ModuleConfig::OPTION_REQUIRE_PUSHED_AUTHORIZATION_REQUESTS` - optional,
require PAR globally (default `false`).
- `ModuleConfig::OPTION_REQUIRE_SIGNED_REQUEST_OBJECT` - optional, require every
Request Object to be signed, rejecting `alg: none` (default `false`).
- `ModuleConfig::OPTION_REQUEST_URI_PARAMETER_SUPPORTED` - optional, support
passing a Request Object by reference via an `https://` `request_uri`; set to
`false` to disable all outbound fetches (default `true`).
- `ModuleConfig::OPTION_REQUEST_URI_FETCH_TIMEOUT` - optional, timeout in seconds
for fetching a remote `request_uri` (default `5`).
- `ModuleConfig::OPTION_REQUEST_URI_MAX_SIZE_BYTES` - optional, maximum allowed
response size in bytes when fetching a remote `request_uri` (default `102400`).
- `ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES` - optional,
SSRF/DoS allowlist of `request_uri` prefixes for OpenID Federation candidates;
`[]` (default) denies all such fetches, a non-empty array allows matching
prefixes, and `null` allows any (not recommended).
- `ModuleConfig::OPTION_ENCRYPTION_KEY` - optional, ASCII-safe string
representation of a `\Defuse\Crypto\Key` to use as the encryption key. If not
set (default), the SimpleSAMLphp secret salt is used as before. See the config
template for how to generate the key and for the important caveat about
invalidating already-issued artifacts when the key changes.
- Several new options regarding experimental support for OpenID4VCI.

Major impact changes:

- The following configuration options related to the protocol (Connect)
signature algorithm and key pair are removed:
  - `ModuleConfig::OPTION_PKI_PRIVATE_KEY_PASSPHRASE`
  - `ModuleConfig::OPTION_PKI_PRIVATE_KEY_FILENAME`
  - `ModuleConfig::OPTION_PKI_CERTIFICATE_FILENAME`
  - `ModuleConfig::OPTION_TOKEN_SIGNER`
  - `ModuleConfig::OPTION_PKI_NEW_PRIVATE_KEY_PASSPHRASE`
  - `ModuleConfig::OPTION_PKI_NEW_PRIVATE_KEY_FILENAME`
  - `ModuleConfig::OPTION_PKI_NEW_CERTIFICATE_FILENAME`

  Instead of those options, now you must use option
  `ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS` in which you can define
  all supported signature keys for protocol (Connect) purposes.
- The following configuration options related to Federation signature algorithm
and key pair are removed:
  - `ModuleConfig::OPTION_PKI_FEDERATION_PRIVATE_KEY_PASSPHRASE`
  - `ModuleConfig::OPTION_PKI_FEDERATION_PRIVATE_KEY_FILENAME`
  - `ModuleConfig::OPTION_PKI_FEDERATION_CERTIFICATE_FILENAME`
  - `ModuleConfig::OPTION_FEDERATION_TOKEN_SIGNER`
  - `ModuleConfig::OPTION_PKI_FEDERATION_NEW_PRIVATE_KEY_PASSPHRASE`
  - `ModuleConfig::OPTION_PKI_FEDERATION_NEW_PRIVATE_KEY_FILENAME`
  - `ModuleConfig::OPTION_PKI_FEDERATION_NEW_CERTIFICATE_FILENAME`

  Instead of those options, now you must use option
  `ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS` in which you can define
  all the supported signature keys for Federation purposes.
- Config option `ModuleConfig::OPTION_HOMEPAGE_URI` is removed. Use
`ModuleConfig::OPTION_ORGANIZATION_URI` instead.
- New algorithm for generating Key ID claim value (`kid`) for signature keys
is used. Previously, key ID was based on public key file hash. In v7, key ID
is a thumbprint of the public key as per
https://datatracker.ietf.org/doc/html/rfc7638. If you want to keep using your
current signature keys, you will probably want to keep the old `kid` values,
so that the clients know the keys did not change. You can set the old
`kid` value manually for signature keys in
`ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS` and
`ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS`. Once you do a key
roll-over, you can omit setting the `kid` manually, so you start using the
automatically generated thumbprint.
- In v6 of the module, when defining custom scopes, there was a possibility to
use standard claims with the 'are_multiple_claim_values_allowed' option.
This would allow multiple values (array of values) for standard claims which
have a single value by specification. All [standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
are now hardcoded to have a single value, even when the
'are_multiple_claim_values_allowed' option is enabled.
- OpenID Federation specific endpoints for subordinate listing and fetching
statements about subordinates are removed, as the final specification
explicitly states that leaf entities must not have those endpoints.
This effectively means that this OP implementation can only be a leaf entity
in the federation context, and not a federation operator or intermediary entity.
- The legacy OIDC endpoints served directly by PHP files in the module's
`public` folder are now removed (as announced in the version 5 to 6 upgrade
notes). These were the old routes still reachable at URLs ending in `.php`:
  - `<basepath>/module.php/oidc/authorize.php`
  - `<basepath>/module.php/oidc/token.php`
  - `<basepath>/module.php/oidc/userinfo.php`
  - `<basepath>/module.php/oidc/jwks.php`
  - `<basepath>/module.php/oidc/logout.php`
  - `<basepath>/module.php/oidc/openid-configuration.php`

  Use the Symfony-based routes instead, which have been the default since
  version 6 and are the ones advertised in the OP Configuration
  (`.well-known/openid-configuration`) endpoint:
  - `<basepath>/module.php/oidc/authorization`
  - `<basepath>/module.php/oidc/token`
  - `<basepath>/module.php/oidc/userinfo`
  - `<basepath>/module.php/oidc/jwks`
  - `<basepath>/module.php/oidc/end-session`
  - `<basepath>/module.php/oidc/.well-known/openid-configuration`

  Any relying party still calling the old `.php` URLs must be updated to the
  new routes. Note that since version 6 the OP has been publishing the new
  routes in its discovery metadata, so RPs that read the OP Configuration
  dynamically need no change.

Medium impact changes:

Low-impact changes:
- The token endpoint no longer requires the `client_id` request parameter when
the client identity is conveyed by the client authentication method itself, in
line with the specifications. For example, with `private_key_jwt` the client is
identified by the assertion's `iss`/`sub` claims, and with `client_secret_basic`
by the `Authorization` header. Requests that still send `client_id` are
unaffected, and the authenticated client is always validated against the client
the authorization code was issued to. Note that for non-registered (generic VCI)
clients the `client_id` parameter is still required, as their identity cannot be
derived from a credential.
- Client property `is_federated` has been removed, as the OP implementation
can now only be a leaf entity in the federation context, and not a federation
operator or intermediary entity. Previously, this property was used to
indicate whether the client is a federated client or not, but now it is not
needed since the OP implementation can only be a leaf entity
- Admin menu item "OIDC" has been renamed to "OIDC OP" to better reflect
the main purpose of the module.
- RP-initiated logout requests that include a `post_logout_redirect_uri` but
omit `id_token_hint` are no longer rejected. Per the
[RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
spec, `id_token_hint` is RECOMMENDED (not required), and without it the OP must
not perform post-logout redirection. Previously the OP threw an error in this
case (which also aborted the logout). Now the end user is logged out as usual
and shown the module's own "you are logged out" page instead of being
redirected. Requests that do include `id_token_hint` are unchanged: the
`post_logout_redirect_uri` is still validated against the client's registered
values, and the redirection is performed as before.

## Version 6.3 to 6.4

This is a minor release in order to enable installation of the module with
SimpleSAMLphp v2.5.*, which now requires at least PHP v8.3 and bumps a bunch
of dependent Symfony packages to v7.4.

## Version 5 to 6

New features:

- Caching support for OIDC protocol artifacts like Access Tokens,
Authorization Codes, Refresh Tokens, but also client and user data.
The cache layer stands in front of the database store, so it can
improve performance, especially in cases of a sudden surge of
users trying to authenticate. Implementation is based on a Symfony
Cache component, so any compatible Symfony cache adapter can be used.
Check the module config file for more information on how to set the
protocol cache.
- Key rollover support - you can now define an additional (new)
private / public key pair which will be published on the relevant
JWKS endpoint or contained in JWKS property. In this way, you can
"announce" a new public key which can then be fetched by RPs,
and do the switch between "old" and "new" key pair when you
find appropriate.
- OpenID Federation capabilities:
  - Automatic client registration using a Request Object (passing it by value)
  - Federation participation limiting based on Trust Marks
  - Endpoint for issuing a configuration entity statement
  (statement about itself)
  - Fetch endpoint for issuing statements about subordinates
  (registered clients)
  - (from v6.1) Subordinate listing endpoint
  - Clients can now be configured with new properties:
    - Entity Identifier
    - Supported OpenID Federation Registration Types
    - Federation JWKS
    - Protocol JWKS, JWKS URI, and Signed JWKS URI,
    - Registration type (manual, federated_automatic, or other in the future)
    - Is Federated flag (indicates participation in federation context)
    - Timestamps: created_at, updated_at, expires_at
- Improved AuthProc filter support
  - Support authproc filters that need to redirect and later resume processing
    - `consent` and `preprodwarning` are two authprocs that redirect for
    user interaction and are now supported
  - Uses SSP's ProcessingChain class for closer alignment with SAML IdP
  configuration.
    - Allows additional configuration of authprocs in the main
    `config.php` under key `authproc.oidc`
- Authorization endpoint now also supports sending request parameters using
HTTP POST method, in addition to GET.
- Added support for passing authorization request parameters as JWTs,
specifically - passing a Request Object by Value:
[https://openid.net/specs/openid-connect-core-1_0.html#RequestObject](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject)
- Added support for `private_key_jwt` client authentication method at
token endpoint:
[https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)

New configuration options:

- (from v6.1) Show `claims_supported` claim in OP Discovery endpoint -
you can now choose to show supported claims, as is recommended by OpenID
Connect Discovery specification
[https://openid.net/specs/openid-connect-discovery-1_0.html](https://openid.net/specs/openid-connect-discovery-1_0.html).
- (optional) Issuer - you can now override the issuer (OP identifier).
If not set, it falls back to the current scheme, host, and optionally
a port (as in all previous module versions).
- (optional) Protocol caching adapter and its arguments
- (optional) OpenID Federation-related options (needed if federation
capabilities are to be used):
  - enabled or disabled federation capabilities
  - valid trust anchors
  - authority hints
  - federation caching adapter and its arguments
  - PKI keys - federation keys used, for example, to sign federation entity
  statements
  - federation participation limiting based on Trust Marks for RPs
  - (from v6.1) own Trust Marks to dynamically fetch
  - (from v6.3) Trust Mark Status Endpoint Usage Policy
  - signer algorithm
  - entity statement duration
  - organization name
  - display name
  - description
  - keywords
  - contacts
  - logo URI
  - policy URI
  - information URI
  - homepage URI (renamed to organization_uri in draft-43)
  - organization URI

Major impact changes:

- PHP version requirement was bumped to v8.2

Medium impact changes:

- Database schema has been updated, so you'll have to run the DB migrations
as described in the README file.
- OIDC protocol endpoints ('authorization_endpoint', 'token_endpoint',
'userinfo_endpoint', 'end_session_endpoint', 'jwks_uri') are now available as
new routes which use Symfony routing and container mechanism. This was done as
an effort to move to the default SimpleSAMLphp way of working with routes and
services. New routes are now published by default in "OP Configuration"
endpoint, which is now also available as
`<basepath>/module.php/oidc/.well-known/openid-configuration`. If you are
publishing that URL as a "well-known" URL ('/.well-known/openid-configuration'),
make sure to update your web server configuration to reflect that change
(you can refer to README for examples). All old routes (routes served by
PHP files in the public folder) will stay available in this version,
which should allow all RPs to update OP configuration in time.
Old routes will be removed in version 7.
- If you are using Apache web server: you should check the README file which
now contains a note on how to configure Apache to preserve Authorization
HTTP headers with a Bearer token scheme (stripping of this header in Apache is a
known [issue](https://github.com/symfony/symfony/issues/19693)). If you don't
set this config, you'll now get warnings about this situation in your logs.
The new authproc filter processing will look in an additional location for
filters, in the main `config.php` under key `authproc.oidc`
- Removed support for plain OAuth2 Implicit flow (response_type `token`),
because of very low usage. Note that the OIDC Implicit flow is still supported
(response_type `id_token token` or `id_token`).

Low-impact changes:

- In an effort to move to SimpleSAMLphp way of working with user interface (UI),
the client management UI was updatedto extend from the SimpleSAMLphp base
template. In addition, we have also introduced some configuration overview
pages where you can take a quick view of some of the configuration values for
the module. OIDC related pages are now available from the main SimpleSAMLphp
menu in the Administration area.
- The OIDC config template file has been moved from
`config-templates/module_oidc.php` to `config/module_oidc.php.dist`.
This is only relevant for new installations, since initially it is necessary
to copy the template file to the default SSP config dir.
- (from v6.3) A new option for Trust Mark Status Endpoint Usage Policy has
been introduced, which can be used to control how the Trust Mark Status
Endpoint is used when validating Trust Marks. The default value is
`RequiredIfEndpointProvidedForNonExpiringTrustMarksOnly`, which
means that the Trust Mark Status Endpoint is only used if the
endpoint is provided by the Trust Mark Issuer, and the Trust
Mark does not expire.

Below are also some internal changes that should not have an impact on the
OIDC OP implementers. However, if you are using this module as a library or
extending from it, you will probably encounter breaking changes, since a lot
of code has been refactored:

- Upgraded to v5 of [lcobucci/jwt](https://github.com/lcobucci/jwt)
- Upgraded to v3 of [laminas/laminas-diactoros](https://github.com/laminas/laminas-diactoros)
- SimpleSAMLphp version used during development was bumped to v2.3
- In Authorization Code Flow, a new validation was added which checks for
'openid' value in the 'scope' parameter. Up to now, the 'openid' value was
dynamically added if not present. In Implicit Code Flow this validation was
already present.
- Removed importer from the legacy OAuth2 module, as it is very unlikely that
someone will upgrade from the legacy OAuth2 module to v6 of oidc module.
If needed, one can upgrade to earlier versions of the `oidc` module, and then
to v6.

## Version 4 to 5

Major impact changes:

- PHP version requirement was bumped to v8.1

Medium impact changes:

- Module config options in the file 'module_oidc.php' are now using constants
for config keys. The values for constants are taken from the previous version
of the module, so theoretically you don't have to rewrite your current config
file, although it is recommended to do so.

Low-impact changes:

- Removed the 'kid' config option which was not used in the codebase
(from v2 of the module, the 'kid' value is the fingerprint of the certificate).

Below are some internal changes that should not have an impact on the OIDC OP
implementers. However, if you are using this module as a library or extending
from it, you will probably encounter breaking changes, since a lot of code
has been refactored:

- psalm error level set to 1, which needed a fair number of code adjustments
- refactored to strict typing whenever possible (psalm can now infer
types for >99% of the codebase)
- refactored to PHP v8.* (up to PHP v8.1) code styling whenever possible,
like using constructor property promotion, match expressions...
- removed dependency on steverhoades/oauth2-openid-connect-server
(low maintenance)

## Version 3 to 4

- PHP version requirement was bumped to v8.0 to enable updating important
dependent packages like 'league/oauth2-server' which has already moved to
PHPv8 between their minor releases.
- SimpleSAMLphp version used during development was bumped v2.0

## Version 2 to 3

- Module code was refactored to make it compatible with SimpleSAMLphp v2
- The default key name was changed from oidc_module.pem to oidc_module.key.
If you don't set a custom key name using the option 'privatekey' in a module
config file, make sure to change the file name of the key from
oidc_module.pem to oidc_module.key.
- Removed config option 'alwaysIssueRefreshToken'
- Removed config option 'alwaysAddClaimsToIdToken'

## Version 1 to 2

There are many DB changes that need to be applied. Perform the migration by
logging in as an SSP admin to
[https://server/simplesaml/module.php/oidc/install.php](https://server/simplesaml/module.php/oidc/install.php)

An SSP admin should now use
[https://server/simplesaml/module.php/oidc/admin-clients/](https://server/simplesaml/module.php/oidc/admin-clients/)
to manage clients. The previous `/clients/` path is for authorized users.

Review the changes to `config-templates/module_oidc.php` and apply relevant
changes to your configuration. For example, claim types are now supported.

In version 1, in authorization code flow, user claims were always included in
ID token, instead of only including them if the access token was not released,
as per specification. Since changing this behavior is a potential breaking
change for Relying Parties, in version 2 a config option
'alwaysAddClaimsToIdToken' is introduced to enable OpenID Providers to keep
the behavior from version 1 by setting it to 'true'.
If 'alwaysAddClaimsToIdToken' is set to 'false', user claims will only be added
to ID token if access token was not released. If an access token was released,
user claims will have to be fetched from the 'userinfo' endpoint.
Note that this option has only applied to authorization code flow since
implicit flow was not available in version 1. If you are to use the spec
compliant behavior, make sure to warn existing Relying Parties about the change.

Similarly, in version 1, in authorization code flow, the refresh token was
always released, instead of only releasing it if the client specifically
requested it using the 'offline_access' scope. Since changing this
behavior is a potential breaking change for Relying Parties, in version 2
a config option 'alwaysIssueRefreshToken' is introduced to enable OpenID
Providers to keep the behavior from version 1 by setting it to 'true'.
If 'alwaysIssueRefreshToken' is set to 'false', refresh token will be released
only if it was requested using 'offline_access' scope. If you are to use the
spec compliant behavior, make sure to warn existing Relying Parties about
the change. Note that in that case the client must have the
'offline_access' scope registered.

Token endpoint was renamed from '.../access_token.php' to '.../token.php'.
This is a potential breaking change for clients that do not fetch
OP configuration from the /.well-known/openid-configuration URI dynamically,
but instead hardcode endpoints in their configuration. You should probably
warn existing Relying Parties about this change.

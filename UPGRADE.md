# TODO
- upgrade to v9 of oauth2-server https://github.com/thephpleague/oauth2-server/releases/tag/9.0.0
- implement key rollover
- implement token introspection
- implement dynamic client registration
- move request rules to templates (generics) for proper static type handling
- remove dependency on laminas/laminas-httphandlerrunner
- create a bridge towards SSP utility classes, so they can be easily mocked
- move away from SSP database as store; move to DBAL
- move to phpstan instead of psalm (as SSP)

# Version 5 to 6

## New features

- OpenID capabilities
  - New federation endpoints:
    - endpoint for issuing configuration entity statement (statement about itself)
    - fetch endpoint for issuing statements about subordinates (registered clients)
  - Clients can now be configured with new properties:
    - Entity Identifier
    - Supported OpenID Federation Registration Types
    - Federation JWKS
    - Protocol JWKS, JWKS URI and Signed JWKS URI,
    - Registration type (manual, federated_automatic, or other in the future)
    - Is Federated flag (indicates participation in federation context)
    - Timestamps: created_at, updated_at, expires_at
- Improved AuthProc filter support
  - Support authproc filters that need to redirect and later resume processing
    - `consent` and `preprodwarning` are two authprocs that redirect for user interaction and are now supported
  - Uses SSP's ProcessingChain class for closer alignment with SAML IdP configuration.
    - Allows additional configuration of authprocs in the main `config.php` under key `authproc.oidc`
- Authorization endpoint now also supports sending request parameters using HTTP POST method, in addition to GET.
- Added support for passing authorization request parameters as JWTs, specifically - passing a Request Object by Value:
https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
- Added support for `private_key_jwt` client authentication method at token endpoint:
https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication

## New configuration options

- (optional) Issuer - you can now override the issuer (OP identifier). If not set, it falls back to current scheme, host
and optionally a port (as in all previous module versions).
- protocol caching adapter and its arguments
- (optional) OpenID Federation related options (needed if federation capabilities are to be used):
  - enabled or disabled federation capabilities
  - valid trust anchors
  - authority hints
  - federation caching adapter and its arguments
  - PKI keys - federation keys used for example to sign federation entity statements
  - signer algorithm
  - entity statement duration
  - organization name
  - contacts
  - logo URI
  - policy URI
  - homepage URI

## Major impact changes

- PHP version requirement was bumped to v8.2

## Medium impact changes

- Database schema has been updated, so you'll have to run the DB migrations as described in the README file.
- OIDC protocol endpoints ('authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'end_session_endpoint',
'jwks_uri') are now available as new routes which use Symfony routing and container mechanism. This was done as an
effort to move to default SimpleSAMLphp way of working with routes and services. New routes are now published by
default in "OP Configuration" endpoint, which is now also available as
`<basepath>/module.php/oidc/.well-known/openid-configuration`. If you are publishing that URL as a "well-known" URL
('/.well-known/openid-configuration'), make sure to update your web server configuration to reflect that change
(you can refer to README for examples). All old routes (routes served by PHP files in public folder) will stay
available in this version, which should allow all RPs to update OP configuration in time. Old routes will be
removed in version 7.
- If you are using Apache web server: you should check the README file which now contains a note on how to configure
Apache to preserve Authorization HTTP headers with Bearer token scheme (stripping of this header in Apache is a
known 'issue': https://github.com/symfony/symfony/issues/19693). If you don't set this config, you'll now get warnings
about this situation in your logs.
- The new authproc filter processing will look in an additional location for filters, in the main `config.php` under 
key `authproc.oidc`

## Low impact changes

In an effort to move to SimpleSAMLphp way of working with user interface (UI), the client management UI was updated
to extend from the SimpleSAMLphp base template. In addition, we have also introduced some configuration overview pages
where you can take a quick view of some of the configuration values for the module. OIDC related pages are now available
from the main SimpleSAMLphp menu in Administration area.  

Below are also some internal changes that should not have impact for the OIDC OP implementors. However, if you are using
this module as a library or extending from it, you will probably encounter breaking changes, since a lot of code
has been refactored:

- upgraded to v5 of lcobucci/jwt https://github.com/lcobucci/jwt
- upgraded to v3 of laminas/laminas-diactoros https://github.com/laminas/laminas-diactoros
- SimpleSAMLphp version used during development was bumped to v2.2
- In Authorization Code Flow, a new validation was added which checks for 'openid' value in 'scope' parameter. Up to
now, 'openid' value was dynamically added if not present. In Implicit Code Flow this validation was already present. 

# Version 4 to 5

## Major impact changes
- PHP version requirement was bumped to v8.1

## Medium impact changes
- Module config options in file 'module_oidc.php' are now using constants for config keys. The values for constants are
taken from the previous version of the module, so theoretically you don't have to rewrite your current config file,
although it is recommended to do so.

## Low impact changes
- Removed the 'kid' config option which was not utilized in the codebase (from v2 of the module, the 'kid' value is the
fingerprint of the certificate).

Below are some internal changes that should not have impact for the OIDC OP implementors. However, if you are using
this module as a library or extending from it, you will probably encounter breaking changes, since a lot of code
has been refactored:

- psalm error level set to 1, which needed a fair amount of code adjustments
- refactored to strict typing whenever possible (psalm can now infer types for >99% of the codebase)
- refactored to PHP v8.* (up to PHP v8.1) code styling whenever possible, like using constructor property promotion, 
match expressions...
- removed dependency on steverhoades/oauth2-openid-connect-server (low maintenance)

# Version 3 to 4
- PHP version requirement was bumped to v8.0 to enable updating important dependant packages like 'league/oauth2-server'
  which has already moved to PHPv8 between their minor releases.
- SimpleSAMLphp version used during development was bumped v2.0

# Version 2 to 3
 - Module code was refactored to make it compatible with SimpleSAMLphp v2
 - Default key name was changed from oidc_module.pem to oidc_module.key. If you don't set custom
key name using option 'privatekey' in module config file, make sure to change the file name of the
key from oidc_module.pem to oidc_module.key.
 - Removed config option 'alwaysIssueRefreshToken'
 - Removed config option 'alwaysAddClaimsToIdToken'

# Version 1 to 2

There are numerous DB changes that need to be applied. Perform the migration by logging in as an SSP admin to
https://server/simplesaml/module.php/oidc/install.php

An SSP admin should now use https://server/simplesaml/module.php/oidc/admin-clients/ to manage clients. 
The previous `/clients/` path is for authorized users.

Review the changes to `config-templates/module_oidc.php` and apply relevant changes to your configuration. 
For example claim types are now supported. 

In version 1, in authorization code flow, user claims were always included in ID token, instead of only
including them if access token was not released, as per specification. Since changing this behavior is a 
potential breaking change for Relying Parties, in version 2 a config option 'alwaysAddClaimsToIdToken' is 
introduced to enable OpenID Providers to keep the behavior from version 1 by setting it to 'true'.
If 'alwaysAddClaimsToIdToken' is set to 'false', user claims will only be added to ID token if access token was
not released. If access token was released, user claims will have to be fetched from 'userinfo' endpoint.
Note that this option only applies to authorization code flow since implicit flow was not available in version 1.
If you are to use the spec compliant behavior, make sure to warn existing Relying Parties about the change.

Similarly, in version 1, in authorization code flow, refresh token was always released, instead of only
releasing it if the client specifically requested it using 'offline_access' scope. Since changing this
behavior is a potential breaking change for Relying Parties, in version 2 a config option
'alwaysIssueRefreshToken' is introduced to enable OpenID Providers to keep the behavior from version 1
by setting it to 'true'. If 'alwaysIssueRefreshToken' is set to 'false', refresh token will be released 
only if it was requested using 'offline_access' scope. If you are to use the spec compliant behavior, make
sure to warn existing Relying Parties about the change. Note that in that case the client must have the
'offline_access' scope registered.

Token endpoint was renamed from '.../access_token.php' to '.../token.php'. This is a potential breaking change
for clients that do not fetch OP configuration from the /.well-known/openid-configuration URI dynamically, but
instead hardcode endpoints in their configuration. You should probably warn existing Relying Parties about this 
change.

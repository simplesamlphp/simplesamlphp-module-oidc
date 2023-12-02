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
- SimpleSAMLphp version requirement fixed to v2.0.*

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

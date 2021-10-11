
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

Token endpoint was renamed from '.../access_token.php' to '.../token.php'. This is a potential breaking change
for clients that do not fetch OP configuration from the /.well-known/openid-configuration URI dynamically, but
instead hardcode endpoints in their configuration. You should probably warn existing Relying Parties about this 
change.

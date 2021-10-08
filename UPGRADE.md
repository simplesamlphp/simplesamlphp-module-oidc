
# Version 1 to 2

There are numerous DB changes that need to be applied. Perform the migration be logging in as an SSP admin to
https://server/simplesaml/module.php/oidc/install.php

An SSP admin should now use https://server/simplesaml/module.php/oidc/admin-clients/ to manage clients. The previous `/clients/` path
is for authorized users.

Review the changes to `config-templates/module_oidc.php` and apply relevant changes to your configuration. For example claim types are now supported.
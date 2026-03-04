<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum ApiScopesEnum: string
{
    case All = 'all'; // Gives access to the whole API.

    // Verifiable Credential Issuance related scopes.
    case VciAll = 'vci_all'; // Gives access to all VCI-related endpoints.
    case VciCredentialOffer = 'vci_credential_offer'; // Gives access to the credential offer endpoint.
}

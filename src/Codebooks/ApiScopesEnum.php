<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum ApiScopesEnum: string
{
    case All = 'all'; // Gives access to the whole API.

    // Verifiable Credential Issuance related scopes.
    case VciAll = 'vci_all'; // Gives access to all VCI-related endpoints.
    case VciCredentialOffer = 'vci_credential_offer'; // Gives access to the credential offer endpoint.

    // OAuth2 related scopes.
    case OAuth2All = 'oauth2_all'; // Gives access to all OAuth2-related endpoints.
    case OAuth2TokenIntrospection = 'oauth2_token_introspection'; // Gives access to the token introspection endpoint.
}

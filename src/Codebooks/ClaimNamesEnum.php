<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum ClaimNamesEnum: string
{
    case Algorithm = 'alg';
    case AuthorityHints = 'authority_hints';
    case Contacts = 'contacts';
    case ExpirationTime = 'exp';
    case HomepageUri = 'homepage_uri';
    case JsonWebKeySet = 'jwks';
    case KeyId = 'kid';
    case LogoUri = 'logo_uri';
    case Metadata = 'metadata';
    case OrganizationName = 'organization_name';
    case PolicyUri = 'policy_uri';
    case PublicKeyUse = 'use';
    case Subject = 'sub';
    case Type = 'typ';
}

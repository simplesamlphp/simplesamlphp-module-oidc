<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum ClaimNamesEnum: string
{
    case Algorithm = 'alg';
    case AuthorityHints = 'authority_hints';
    case ExpirationTime = 'exp';
    case JsonWebKeySet = 'jwks';
    case KeyId = 'kid';
    case Metadata = 'metadata';
    case PublicKeyUse = 'use';
    case Subject = 'sub';
    case Type = 'typ';
}

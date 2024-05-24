<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks\ClaimValues;

enum PublicKeyUseEnum: string
{
    case Signature = 'sig';
    case Encryption = 'enc';
}

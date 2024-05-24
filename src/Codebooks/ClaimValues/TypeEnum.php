<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks\ClaimValues;

enum TypeEnum: string
{
    case EntityStatementJwt = 'entity-statement+jwt';
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum LimitsEnum: string
{
    case OneOf = 'one_of';
    case AllOf = 'all_of';
}

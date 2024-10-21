<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\TokenIssuers;

use SimpleSAML\Module\oidc\Helpers;

abstract class AbstractTokenIssuer
{
    public const MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS = 5;

    public function __construct(
        protected readonly Helpers $helpers,
    ) {
    }
}

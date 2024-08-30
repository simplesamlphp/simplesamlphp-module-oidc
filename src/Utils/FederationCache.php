<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use Psr\SimpleCache\CacheInterface;

readonly class FederationCache
{
    public function __construct(
        public CacheInterface $instance,
    ) {
    }
}

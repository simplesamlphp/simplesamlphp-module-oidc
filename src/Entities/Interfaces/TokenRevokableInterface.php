<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities\Interfaces;

interface TokenRevokableInterface
{
    /**
     * Check if token is revoked.
     * @return bool
     */
    public function isRevoked(): bool;

    /**
     * Revoke token
     */
    public function revoke(): void;
}

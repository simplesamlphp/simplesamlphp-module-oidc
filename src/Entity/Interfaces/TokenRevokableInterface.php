<?php

namespace SimpleSAML\Module\oidc\Entity\Interfaces;

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

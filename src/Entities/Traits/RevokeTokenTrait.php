<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities\Traits;

trait RevokeTokenTrait
{
    protected bool $isRevoked = false;

    public function isRevoked(): bool
    {
        return $this->isRevoked;
    }

    /**
     * Revoke token.
     */
    public function revoke(): void
    {
        $this->isRevoked = true;
    }
}

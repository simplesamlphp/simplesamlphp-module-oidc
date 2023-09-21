<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories\Interfaces;

use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface as OAuth2RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\RefreshTokenEntityInterface;

interface RefreshTokenRepositoryInterface extends OAuth2RefreshTokenRepositoryInterface
{
    /**
     * Revoke refresh token(s) associated with the given auth code ID.
     */
    public function revokeByAuthCodeId(string $authCodeId): void;

    /**
     * Creates a new refresh token
     */
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface;
}

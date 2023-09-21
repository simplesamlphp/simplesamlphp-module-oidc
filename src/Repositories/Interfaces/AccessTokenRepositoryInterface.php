<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories\Interfaces;

use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface as OAuth2ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface as OAuth2AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\AccessTokenEntityInterface;

interface AccessTokenRepositoryInterface extends OAuth2AccessTokenRepositoryInterface
{
    /**
     * Revoke access token(s) associated with the given auth code ID.
     */
    public function revokeByAuthCodeId(string $authCodeId): void;

    /**
     * Create a new access token
     *
     * @param OAuth2ClientEntityInterface $clientEntity
     * @param OAuth2ScopeEntityInterface[] $scopes
     * @param mixed $userIdentifier
     * @param string|null $authCodeId
     * @param array|null $requestedClaims Any requested claims
     * @return AccessTokenEntityInterface
     */
    public function getNewToken(
        OAuth2ClientEntityInterface $clientEntity,
        array $scopes,
        $userIdentifier = null,
        string $authCodeId = null,
        array $requestedClaims = null
    ): AccessTokenEntityInterface;
}

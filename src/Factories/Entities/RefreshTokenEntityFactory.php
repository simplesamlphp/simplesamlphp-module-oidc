<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\RefreshTokenEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

class RefreshTokenEntityFactory
{
    public function __construct(
        protected Helpers $helpers,
    ) {
    }

    public function fromData(
        string $id,
        DateTimeImmutable $expiryDateTime,
        AccessTokenEntityInterface $accessTokenEntity,
        ?string $authCodeId = null,
        bool $isRevoked = false,
    ): RefreshTokenEntity {
        return new RefreshTokenEntity(
            $id,
            $expiryDateTime,
            $accessTokenEntity,
            $authCodeId,
            $isRevoked,
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function fromState(array $state): RefreshTokenEntity
    {
        if (
            !is_string($state['id']) ||
            !is_string($state['expires_at']) ||
            !is_a($state['access_token'], AccessTokenEntityInterface::class)
        ) {
            throw OidcServerException::serverError('Invalid Refresh Token state');
        }

        $id = $state['id'];
        $expiryDateTime = $this->helpers->dateTime()->getUtc($state['expires_at']);
        $accessToken = $state['access_token'];
        $isRevoked = (bool) $state['is_revoked'];
        $authCodeId = empty($state['auth_code_id']) ? null : (string)$state['auth_code_id'];

        return $this->fromData(
            $id,
            $expiryDateTime,
            $accessToken,
            $authCodeId,
            $isRevoked,
        );
    }
}

<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Repositories;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface as OAuth2RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use RuntimeException;
use SimpleSAML\Module\oidc\Entity\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Entity\RefreshTokenEntity;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Traits\RevokeTokenByAuthCodeIdTrait;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

class RefreshTokenRepository extends AbstractDatabaseRepository implements RefreshTokenRepositoryInterface
{
    use RevokeTokenByAuthCodeIdTrait;

    final public const TABLE_NAME = 'oidc_refresh_token';

    /**
     * @return string
     */
    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    /**
     * {@inheritdoc}
     */
    public function getNewRefreshToken(): RefreshTokenEntityInterface
    {
        return new RefreshTokenEntity();
    }

    /**
     * {@inheritdoc}
     * @throws OAuthServerException
     */
    public function persistNewRefreshToken(OAuth2RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        if (!$refreshTokenEntity instanceof RefreshTokenEntity) {
            throw OAuthServerException::invalidRefreshToken();
        }

        $stmt = sprintf(
            "INSERT INTO %s (id, expires_at, access_token_id, is_revoked, auth_code_id) "
                . "VALUES (:id, :expires_at, :access_token_id, :is_revoked, :auth_code_id)",
            $this->getTableName()
        );

        $this->database->write(
            $stmt,
            $refreshTokenEntity->getState()
        );
    }

    /**
     * Find Refresh Token by id.
     */
    public function findById(string $tokenId): ?RefreshTokenEntityInterface
    {
        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $tokenId,
            ]
        );

        if (empty($rows = $stmt->fetchAll())) {
            return null;
        }

        /** @var array $data */
        $data = current($rows);
        $accessTokenRepository = new AccessTokenRepository($this->moduleConfig);
        $data['access_token'] = $accessTokenRepository->findById((string)$data['access_token_id']);

        return RefreshTokenEntity::fromState($data);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeRefreshToken($tokenId): void
    {
        $refreshToken = $this->findById($tokenId);

        if (!$refreshToken) {
            throw new RuntimeException("RefreshToken not found: $tokenId");
        }

        $refreshToken->revoke();
        $this->update($refreshToken);
    }

    /**
     * {@inheritdoc}
     */
    public function isRefreshTokenRevoked($tokenId): bool
    {
        $refreshToken = $this->findById($tokenId);

        if (!$refreshToken) {
            throw new RuntimeException("RefreshToken not found: $tokenId");
        }

        return $refreshToken->isRevoked();
    }

    /**
     * Removes expired refresh tokens.
     */
    public function removeExpired(): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE expires_at < :now",
            [
                'now' => TimestampGenerator::utc()->format('Y-m-d H:i:s'),
            ]
        );
    }

    private function update(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $stmt = sprintf(
            "UPDATE %s SET expires_at = :expires_at, access_token_id = :access_token_id, is_revoked = :is_revoked, "
                . "auth_code_id = :auth_code_id WHERE id = :id",
            $this->getTableName()
        );

        $this->database->write(
            $stmt,
            $refreshTokenEntity->getState()
        );
    }
}

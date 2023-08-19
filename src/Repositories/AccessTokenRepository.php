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

use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use RuntimeException;
use SimpleSAML\Error\Error;
use SimpleSAML\Module\oidc\Entity\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entity\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Traits\RevokeTokenByAuthCodeIdTrait;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

class AccessTokenRepository extends AbstractDatabaseRepository implements AccessTokenRepositoryInterface
{
    use RevokeTokenByAuthCodeIdTrait;

    public const TABLE_NAME = 'oidc_access_token';

    /**
     * {@inheritdoc}
     */
    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    /**
     * {@inheritdoc}
     */
    public function getNewToken(
        OAuth2ClientEntityInterface $clientEntity,
        array $scopes,
        $userIdentifier = null,
        string $authCodeId = null,
        array $requestedClaims = null
    ): AccessTokenEntityInterface {
        return AccessTokenEntity::fromData($clientEntity, $scopes, $userIdentifier, $authCodeId, $requestedClaims);
    }

    /**
     * {@inheritdoc}
     * @throws Error
     */
    public function persistNewAccessToken(OAuth2AccessTokenEntityInterface $accessTokenEntity): void
    {
        if (!$accessTokenEntity instanceof AccessTokenEntity) {
            throw new Error('Invalid AccessTokenEntity');
        }

        $stmt = sprintf(
            "INSERT INTO %s (id, scopes, expires_at, user_id, client_id, is_revoked, auth_code_id, requested_claims) "
            . "VALUES (:id, :scopes, :expires_at, :user_id, :client_id, :is_revoked, :auth_code_id, :requested_claims)",
            $this->getTableName()
        );

        $this->database->write(
            $stmt,
            $accessTokenEntity->getState()
        );
    }

    /**
     * Find Access Token by id.
     */
    public function findById(string $tokenId): ?AccessTokenEntity
    {
        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $tokenId,
            ]
        );

        if (!$rows = $stmt->fetchAll()) {
            return null;
        }

        $data = current($rows);
        $clientRepository = new ClientRepository($this->configurationService);
        $data['client'] = $clientRepository->findById($data['client_id']);

        return AccessTokenEntity::fromState($data);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken($tokenId): void
    {
        $accessToken = $this->findById($tokenId);

        if (!$accessToken instanceof AccessTokenEntity) {
            throw new RuntimeException("AccessToken not found: $tokenId");
        }

        $accessToken->revoke();
        $this->update($accessToken);
    }

    /**
     * {@inheritdoc}
     */
    public function isAccessTokenRevoked($tokenId): bool
    {
        $accessToken = $this->findById($tokenId);

        if (!$accessToken) {
            throw new RuntimeException("AccessToken not found: $tokenId");
        }

        return $accessToken->isRevoked();
    }

    /**
     * Removes expired access tokens.
     */
    public function removeExpired(): void
    {
        $accessTokenTableName = $this->getTableName();
        $refreshTokenTableName = $this->database->applyPrefix(RefreshTokenRepository::TABLE_NAME);

        // Delete expired access tokens, but only if the corresponding refresh token is also expired.
        $this->database->write(
            "DELETE FROM $accessTokenTableName WHERE expires_at < :now AND
                NOT EXISTS (
                    SELECT 1 FROM {$refreshTokenTableName}
                    WHERE $accessTokenTableName.id = $refreshTokenTableName.access_token_id AND expires_at > :now
                )",
            [
                'now' => TimestampGenerator::utc()->format('Y-m-d H:i:s'),
            ]
        );
    }

    private function update(AccessTokenEntity $accessTokenEntity): void
    {
        $stmt = sprintf(
            "UPDATE %s SET scopes = :scopes, expires_at = :expires_at, user_id = :user_id, "
                . "client_id = :client_id, is_revoked = :is_revoked, auth_code_id = :auth_code_id, "
                . "requested_claims = :requested_claims WHERE id = :id",
            $this->getTableName()
        );

        $this->database->write(
            $stmt,
            $accessTokenEntity->getState()
        );
    }
}

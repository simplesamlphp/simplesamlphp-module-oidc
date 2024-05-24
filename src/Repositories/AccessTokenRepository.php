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

use Exception;
use JsonException;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use RuntimeException;
use SimpleSAML\Error\Error;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Traits\RevokeTokenByAuthCodeIdTrait;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

class AccessTokenRepository extends AbstractDatabaseRepository implements AccessTokenRepositoryInterface
{
    use RevokeTokenByAuthCodeIdTrait;

    final public const TABLE_NAME = 'oidc_access_token';

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
        array $requestedClaims = null,
    ): AccessTokenEntityInterface {
        if (!is_null($userIdentifier)) {
            $userIdentifier = (string)$userIdentifier;
        }
        if (empty($userIdentifier)) {
            $userIdentifier = null;
        }
        return AccessTokenEntity::fromData($clientEntity, $scopes, $userIdentifier, $authCodeId, $requestedClaims);
    }

    /**
     * {@inheritdoc}
     * @throws Error
     * @throws JsonException
     */
    public function persistNewAccessToken(OAuth2AccessTokenEntityInterface $accessTokenEntity): void
    {
        if (!$accessTokenEntity instanceof AccessTokenEntity) {
            throw new Error('Invalid AccessTokenEntity');
        }

        $stmt = sprintf(
            "INSERT INTO %s (id, scopes, expires_at, user_id, client_id, is_revoked, auth_code_id, requested_claims) "
            . "VALUES (:id, :scopes, :expires_at, :user_id, :client_id, :is_revoked, :auth_code_id, :requested_claims)",
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $accessTokenEntity->getState(),
        );
    }

    /**
     * Find Access Token by id.
     * @throws Exception
     * @throws OidcServerException
     */
    public function findById(string $tokenId): ?AccessTokenEntity
    {
        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $tokenId,
            ],
        );

        if (empty($rows = $stmt->fetchAll())) {
            return null;
        }

        /** @var array $data */
        $data = current($rows);
        $clientRepository = new ClientRepository($this->moduleConfig);
        $data['client'] = $clientRepository->findById((string)$data['client_id']);

        return AccessTokenEntity::fromState($data);
    }

    /**
     * {@inheritdoc}
     * @throws JsonException
     * @throws OidcServerException
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
     * @throws OidcServerException
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
     * @throws Exception
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
            ],
        );
    }

    /**
     * @throws JsonException
     */
    private function update(AccessTokenEntity $accessTokenEntity): void
    {
        $stmt = sprintf(
            "UPDATE %s SET scopes = :scopes, expires_at = :expires_at, user_id = :user_id, "
                . "client_id = :client_id, is_revoked = :is_revoked, auth_code_id = :auth_code_id, "
                . "requested_claims = :requested_claims WHERE id = :id",
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $accessTokenEntity->getState(),
        );
    }
}

<?php

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

namespace SimpleSAML\Modules\OpenIDConnect\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\AccessTokenEntity;
use SimpleSAML\Modules\OpenIDConnect\Utils\TimestampGenerator;

class AccessTokenRepository extends AbstractDatabaseRepository implements AccessTokenRepositoryInterface
{
    const TABLE_NAME = 'oidc_access_token';

    /**
     * {@inheritdoc}
     */
    public function getTableName()
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    /**
     * {@inheritdoc}
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null)
    {
        return AccessTokenEntity::fromData($clientEntity, $scopes, $userIdentifier);
    }

    /**
     * {@inheritdoc}
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
        $this->database->write(
            "INSERT INTO {$this->getTableName()} (id, scopes, expires_at, user_id, client_id, is_revoked) VALUES (:id, :scopes, :expires_at, :user_id, :client_id, :is_revoked)",
            $accessTokenEntity->getState()
        );
    }

    /**
     * Find Access Token by id.
     *
     * @param $tokenId
     *
     * @return null|AccessTokenEntity
     */
    public function findById($tokenId)
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
        $data['client'] = (new ClientRepository())->findById($data['client_id']);

        return AccessTokenEntity::fromState($data);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken($tokenId)
    {
        $accessToken = $this->findById($tokenId);

        if (!$accessToken) {
            throw new \RuntimeException("AccessToken not found: {$tokenId}");
        }

        $accessToken->revoke();
        $this->update($accessToken);
    }

    /**
     * {@inheritdoc}
     */
    public function isAccessTokenRevoked($tokenId)
    {
        $accessToken = $this->findById($tokenId);

        if (!$accessToken) {
            throw new \RuntimeException("AccessToken not found: {$tokenId}");
        }

        return $accessToken->isRevoked();
    }

    /**
     * Removes expired access tokens.
     */
    public function removeExpired()
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE expires_at < :now",
            [
                'now' => TimestampGenerator::utc()->format('Y-m-d H:i:s'),
            ]
        );
    }

    private function update(AccessTokenEntity $accessTokenEntity)
    {
        $this->database->write(
            "UPDATE {$this->getTableName()} SET scopes = :scopes, expires_at = :expires_at, user_id = :user_id, client_id = :client_id, is_revoked = :is_revoked WHERE id = :id",
            $accessTokenEntity->getState()
        );
    }
}

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

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\RefreshTokenEntity;
use SimpleSAML\Modules\OpenIDConnect\Utils\TimestampGenerator;

class RefreshTokenRepository extends AbstractDatabaseRepository implements RefreshTokenRepositoryInterface
{
    const TABLE_NAME = 'oidc_refresh_token';

    public function getTableName()
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    public function getNewRefreshToken()
    {
        return new RefreshTokenEntity();
    }

    /**
     * @param RefreshTokenEntityInterface|RefreshTokenEntity $refreshTokenEntity
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity)
    {
        $this->database->write(
            "INSERT INTO {$this->getTableName()} (id, expires_at, access_token_id, is_revoked) VALUES (:id, :expires_at, :access_token_id, :is_revoked)",
            $refreshTokenEntity->getState()
        );
    }

    /**
     * Find Refresh Token by id.
     *
     * @param $tokenId
     *
     * @return null|RefreshTokenEntity
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
        $data['access_token'] = (new AccessTokenRepository())->findById($data['access_token_id']);

        return RefreshTokenEntity::fromState($data);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeRefreshToken($tokenId)
    {
        $refreshToken = $this->findById($tokenId);

        if (!$refreshToken) {
            throw new \RuntimeException("RefreshToken not found: {$tokenId}");
        }

        $refreshToken->revoke();
        $this->update($refreshToken);
    }

    /**
     * {@inheritdoc}
     */
    public function isRefreshTokenRevoked($tokenId)
    {
        $refreshToken = $this->findById($tokenId);

        if (!$refreshToken) {
            throw new \RuntimeException("RefreshToken not found: {$tokenId}");
        }

        return $refreshToken->isRevoked();
    }

    /**
     * Removes expired refresh tokens.
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

    private function update(RefreshTokenEntity $refreshTokenEntity)
    {
        $this->database->write(
            "UPDATE {$this->getTableName()} SET expires_at = :expires_at, access_token_id = :access_token_id, is_revoked = :is_revoked WHERE id = :id",
            $refreshTokenEntity->getState()
        );
    }
}

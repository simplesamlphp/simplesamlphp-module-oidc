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

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\AuthCodeEntity;
use SimpleSAML\Modules\OpenIDConnect\Utils\TimestampGenerator;

class AuthCodeRepository extends AbstractDatabaseRepository implements AuthCodeRepositoryInterface
{
    const TABLE_NAME = 'oidc_auth_code';

    public function getTableName()
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    public function getNewAuthCode()
    {
        return new AuthCodeEntity();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity)
    {
        $this->database->write(
            "INSERT INTO {$this->getTableName()} (id, scopes, expires_at, user_id, client_id, is_revoked, redirect_uri) VALUES (:id, :scopes, :expires_at, :user_id, :client_id, :is_revoked, :redirect_uri)",
            $authCodeEntity->getState()
        );
    }

    /**
     * Find Access Token by id.
     *
     * @param $codeId
     *
     * @return AuthCodeEntityInterface|null
     */
    public function findById($codeId)
    {
        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $codeId,
            ]
        );

        if (!$rows = $stmt->fetchAll()) {
            return null;
        }

        $data = current($rows);
        $data['client'] = (new ClientRepository())->findById($data['client_id']);

        return AuthCodeEntity::fromState($data);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAuthCode($codeId)
    {
        /** @var AuthCodeEntity $authCode */
        $authCode = $this->findById($codeId);

        if (!$authCode) {
            throw new \RuntimeException("AuthCode not found: {$codeId}");
        }

        $authCode->revoke();
        $this->update($authCode);
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthCodeRevoked($tokenId)
    {
        /** @var AuthCodeEntity $authCode */
        $authCode = $this->findById($tokenId);

        if (!$authCode) {
            throw new \RuntimeException("AuthCode not found: {$tokenId}");
        }

        return $authCode->isRevoked();
    }

    /**
     * Removes expired auth codes.
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

    private function update(AuthCodeEntity $authCodeEntity)
    {
        $this->database->write(
            "UPDATE {$this->getTableName()} SET scopes = :scopes, expires_at = :expires_at, user_id = :user_id, client_id = :client_id, is_revoked = :is_revoked, redirect_uri = :redirect_uri WHERE id = :id",
            $authCodeEntity->getState()
        );
    }
}

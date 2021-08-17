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

namespace SimpleSAML\Module\oidc\Repositories;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface as OAuth2AuthCodeEntityInterface;
use SimpleSAML\Error\Assertion;
use SimpleSAML\Module\oidc\Entity\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entity\Interfaces\AuthCodeEntityInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\OidcAuthCodeEntityInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\OidcAuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;


class AuthCodeRepository extends AbstractDatabaseRepository implements AuthCodeRepositoryInterface
{
    public const TABLE_NAME = 'oidc_auth_code';

    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    /**
     * @return AuthCodeEntityInterface
     */
    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCodeEntity();
    }

    /**
     * {@inheritdoc}
     */
    public function persistNewAuthCode(OAuth2AuthCodeEntityInterface $authCodeEntity)
    {
        if (!$authCodeEntity instanceof AuthCodeEntity) {
            throw new Assertion('Invalid AuthCodeEntity');
        }

        $stmt = sprintf(
            "INSERT INTO %s (id, scopes, expires_at, user_id, client_id, is_revoked, redirect_uri, nonce) "
                . "VALUES (:id, :scopes, :expires_at, :user_id, :client_id, :is_revoked, :redirect_uri, :nonce)",
            $this->getTableName()
        );

        $this->database->write(
            $stmt,
            $authCodeEntity->getState()
        );
    }

    /**
     * Find Auth Code by id.
     */
    public function findById(string $codeId): ?AuthCodeEntityInterface
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
        $clientRepository = new ClientRepository($this->configurationService);
        $data['client'] = $clientRepository->findById($data['client_id']);

        return AuthCodeEntity::fromState($data);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAuthCode($codeId)
    {
        $authCode = $this->findById($codeId);

        if (!$authCode instanceof AuthCodeEntity) {
            throw new \RuntimeException("AuthCode not found: {$codeId}");
        }

        $authCode->revoke();
        $this->update($authCode);
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthCodeRevoked($tokenId): bool
    {
        $authCode = $this->findById($tokenId);

        if (!$authCode instanceof AuthCodeEntity) {
            throw new \RuntimeException("AuthCode not found: {$tokenId}");
        }

        return $authCode->isRevoked();
    }

    /**
     * Removes expired auth codes.
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

    /**
     * @return void
     */
    private function update(AuthCodeEntity $authCodeEntity)
    {
        $stmt = sprintf(
            <<<EOS
            UPDATE %s 
            SET 
                scopes = :scopes,
                expires_at = :expires_at,
                user_id = :user_id,
                client_id = :client_id,
                is_revoked = :is_revoked,
                redirect_uri = :redirect_uri,
                nonce = :nonce
            WHERE id = :id
EOS
            ,
            $this->getTableName()
        );

        $this->database->write(
            $stmt,
            $authCodeEntity->getState()
        );
    }
}

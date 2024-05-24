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
use League\OAuth2\Server\Entities\AuthCodeEntityInterface as OAuth2AuthCodeEntityInterface;
use RuntimeException;
use SimpleSAML\Error\Error;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\AuthCodeEntityInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

class AuthCodeRepository extends AbstractDatabaseRepository implements AuthCodeRepositoryInterface
{
    final public const TABLE_NAME = 'oidc_auth_code';

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
     * @throws Error|JsonException
     */
    public function persistNewAuthCode(OAuth2AuthCodeEntityInterface $authCodeEntity): void
    {
        if (!$authCodeEntity instanceof AuthCodeEntity) {
            throw new Error('Invalid AuthCodeEntity');
        }

        $stmt = sprintf(
            "INSERT INTO %s (id, scopes, expires_at, user_id, client_id, is_revoked, redirect_uri, nonce) "
                . "VALUES (:id, :scopes, :expires_at, :user_id, :client_id, :is_revoked, :redirect_uri, :nonce)",
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $authCodeEntity->getState(),
        );
    }

    /**
     * Find Auth Code by id.
     * @throws Exception
     */
    public function findById(string $codeId): ?AuthCodeEntityInterface
    {
        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $codeId,
            ],
        );

        if (empty($rows = $stmt->fetchAll())) {
            return null;
        }

        /** @var array $data */
        $data = current($rows);
        $clientRepository = new ClientRepository($this->moduleConfig);
        $data['client'] = $clientRepository->findById((string)$data['client_id']);

        return AuthCodeEntity::fromState($data);
    }

    /**
     * {@inheritdoc}
     * @throws JsonException
     * @throws Exception
     */
    public function revokeAuthCode($codeId): void
    {
        $authCode = $this->findById($codeId);

        if (!$authCode instanceof AuthCodeEntity) {
            throw new RuntimeException("AuthCode not found: $codeId");
        }

        $authCode->revoke();
        $this->update($authCode);
    }

    /**
     * {@inheritdoc}
     * @throws Exception
     */
    public function isAuthCodeRevoked($codeId): bool
    {
        $authCode = $this->findById($codeId);

        if (!$authCode instanceof AuthCodeEntity) {
            throw new RuntimeException("AuthCode not found: $codeId");
        }

        return $authCode->isRevoked();
    }

    /**
     * Removes expired auth codes.
     * @throws Exception
     */
    public function removeExpired(): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE expires_at < :now",
            [
                'now' => TimestampGenerator::utc()->format('Y-m-d H:i:s'),
            ],
        );
    }

    /**
     * @throws JsonException
     */
    private function update(AuthCodeEntity $authCodeEntity): void
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
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $authCodeEntity->getState(),
        );
    }
}

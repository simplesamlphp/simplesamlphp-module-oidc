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

use League\OAuth2\Server\Entities\AuthCodeEntityInterface as OAuth2AuthCodeEntityInterface;
use PDO;
use RuntimeException;
use SimpleSAML\Database;
use SimpleSAML\Error\Error;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\AuthCodeEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AuthCodeRepositoryInterface;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

class AuthCodeRepository extends AbstractDatabaseRepository implements AuthCodeRepositoryInterface
{
    final public const TABLE_NAME = 'oidc_auth_code';

    public function __construct(
        ModuleConfig $moduleConfig,
        Database $database,
        ?ProtocolCache $protocolCache,
        protected readonly ClientRepository $clientRepository,
        protected readonly AuthCodeEntityFactory $authCodeEntityFactory,
        protected readonly Helpers $helpers,
    ) {
        parent::__construct($moduleConfig, $database, $protocolCache);
    }

    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    /**
     * @return \SimpleSAML\Module\oidc\Entities\Interfaces\AuthCodeEntityInterface
     */
    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        throw new RuntimeException('Not implemented. Use AuthCodeEntityFactory instead.');
    }

    /**
     * {@inheritdoc}
     * @throws \JsonException
     * @throws \SimpleSAML\Error\Error
     */
    public function persistNewAuthCode(OAuth2AuthCodeEntityInterface $authCodeEntity): void
    {
        if (!$authCodeEntity instanceof AuthCodeEntity) {
            throw new Error('Invalid AuthCodeEntity');
        }

        $stmt = sprintf(
            <<<EOS
            INSERT INTO %s (
                id,
                scopes,
                expires_at,
                user_id,
                client_id,
                is_revoked,
                redirect_uri,
                nonce,
                flow_type,
                tx_code,
                authorization_details,
                bound_client_id,
                bound_redirect_uri,
                issuer_state
            ) VALUES (
                :id,
                :scopes,
                :expires_at,
                :user_id,
                :client_id,
                :is_revoked,
                :redirect_uri,
                :nonce,
                :flow_type,
                :tx_code,
                :authorization_details,
                :bound_client_id,
                :bound_redirect_uri,
                :issuer_state
            )
            EOS,
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $this->preparePdoState($authCodeEntity->getState()),
        );

        $this->protocolCache?->set(
            $authCodeEntity->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $authCodeEntity->getExpiryDateTime()->getTimestamp(),
            ),
            $this->getCacheKey((string)$authCodeEntity->getIdentifier()),
        );
    }

    /**
     * Find Auth Code by id.
     * @throws \Exception
     */
    public function findById(string $codeId): ?AuthCodeEntity
    {
        /** @var ?array $data */
        $data = $this->protocolCache?->get(null, $this->getCacheKey($codeId));

        if (!is_array($data)) {
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
        }

        $data['client'] = $this->clientRepository->findById((string)$data['client_id']);

        $authCodeEntity = $this->authCodeEntityFactory->fromState($data);

        $this->protocolCache?->set(
            $authCodeEntity->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $authCodeEntity->getExpiryDateTime()->getTimestamp(),
            ),
            $this->getCacheKey((string)$authCodeEntity->getIdentifier()),
        );

        return $authCodeEntity;
    }

    /**
     * {@inheritdoc}
     * @throws \Exception
     * @throws \JsonException
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
     * @throws \Exception
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
     * @throws \Exception
     */
    public function removeExpired(): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE expires_at < :now",
            [
                'now' => $this->helpers->dateTime()->getUtc()->format(DateFormatsEnum::DB_DATETIME->value),
            ],
        );
    }

    /**
     * @throws \JsonException
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
                nonce = :nonce,
                flow_type = :flow_type,
                tx_code = :tx_code,
                authorization_details = :authorization_details,
                bound_client_id = :bound_client_id,
                bound_redirect_uri = :bound_redirect_uri,
                issuer_state = :issuer_state
            WHERE id = :id
EOS
            ,
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $this->preparePdoState($authCodeEntity->getState()),
        );

        $this->protocolCache?->set(
            $authCodeEntity->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $authCodeEntity->getExpiryDateTime()->getTimestamp(),
            ),
            $this->getCacheKey((string)$authCodeEntity->getIdentifier()),
        );
    }

    protected function preparePdoState(array $state): array
    {
        $isRevoked = (bool)($state['is_revoked'] ?? true);

        $state['is_revoked'] = [$isRevoked, PDO::PARAM_BOOL];

        return $state;
    }
}

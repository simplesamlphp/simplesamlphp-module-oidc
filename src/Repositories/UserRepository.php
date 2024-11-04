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

use DateTimeImmutable;
use Exception;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\Interfaces\IdentityProviderInterface;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

class UserRepository extends AbstractDatabaseRepository implements UserRepositoryInterface, IdentityProviderInterface
{
    final public const TABLE_NAME = 'oidc_user';

    public function __construct(
        ModuleConfig $moduleConfig,
        Database $database,
        ?ProtocolCache $protocolCache,
        protected readonly Helpers $helpers,
        protected readonly UserEntityFactory $userEntityFactory,
    ) {
        parent::__construct($moduleConfig, $database, $protocolCache);
    }

    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    public function getCacheKey(string $identifier): string
    {
        return $this->getTableName() . '_' . $identifier;
    }

    /**
     * @param string $identifier
     *
     * @return \SimpleSAML\Module\oidc\Entities\UserEntity|null
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function getUserEntityByIdentifier(string $identifier): ?UserEntity
    {
        /** @var ?array $cachedState */
        $cachedState = $this->protocolCache?->get(null, $this->getCacheKey($identifier));

        if (is_array($cachedState)) {
            return $this->userEntityFactory->fromState($cachedState);
        }

        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $identifier,
            ],
        );

        if (empty($rows = $stmt->fetchAll())) {
            return null;
        }

        $row = current($rows);

        if (!is_array($row)) {
            return null;
        }

        return $this->userEntityFactory->fromState($row);
    }

    /**
     * {@inheritdoc}
     * @throws \Exception
     */
    public function getUserEntityByUserCredentials(
        $username,
        $password,
        $grantType,
        OAuth2ClientEntityInterface $clientEntity,
    ): ?UserEntityInterface {
        throw new Exception('Not supported');
    }

    public function add(UserEntity $userEntity): void
    {
        $stmt = sprintf(
            "INSERT INTO %s (id, claims, updated_at, created_at) VALUES (:id, :claims, :updated_at, :created_at)",
            $this->getTableName(),
        );
        $this->database->write(
            $stmt,
            $userEntity->getState(),
        );

        $this->protocolCache?->set(
            $userEntity->getState(),
            $this->moduleConfig->getUserEntityCacheDuration(),
            $this->getCacheKey($userEntity->getIdentifier()),
        );
    }

    public function delete(UserEntity $userEntity): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $userEntity->getIdentifier(),
            ],
        );

        $this->protocolCache?->delete($this->getCacheKey($userEntity->getIdentifier()));
    }

    public function update(UserEntity $userEntity, ?DateTimeImmutable $updatedAt = null): void
    {
        $userEntity->setUpdatedAt($updatedAt ?? $this->helpers->dateTime()->getUtc());

        $stmt = sprintf(
            "UPDATE %s SET claims = :claims, updated_at = :updated_at, created_at = :created_at WHERE id = :id",
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $userEntity->getState(),
        );

        $this->protocolCache?->set(
            $userEntity->getState(),
            $this->moduleConfig->getUserEntityCacheDuration(),
            $this->getCacheKey($userEntity->getIdentifier()),
        );
    }
}

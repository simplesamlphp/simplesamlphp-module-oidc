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
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use SimpleSAML\Module\oidc\Entity\UserEntity;

class UserRepository extends AbstractDatabaseRepository implements UserRepositoryInterface, IdentityProviderInterface
{
    public const TABLE_NAME = 'oidc_user';

    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    /**
     * @param string $identifier
     *
     * @return UserEntity|null
     */
    public function getUserEntityByIdentifier($identifier): ?UserEntity
    {
        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $identifier,
            ]
        );

        if (!is_array($rows = $stmt->fetchAll())) {
            return null;
        }

        $row = current($rows);

        if (!is_array($row)) {
            return null;
        }

        return UserEntity::fromState($row);
    }

    /**
     * {@inheritdoc}
     * @throws Exception
     */
    public function getUserEntityByUserCredentials(
        $username,
        $password,
        $grantType,
        OAuth2ClientEntityInterface $clientEntity
    ): ?UserEntityInterface {
        throw new Exception('Not supported');
    }

    public function add(UserEntity $userEntity): void
    {
        $stmt = sprintf(
            "INSERT INTO %s (id, claims, updated_at, created_at) VALUES (:id, :claims, :updated_at, :created_at)",
            $this->getTableName()
        );
        $this->database->write(
            $stmt,
            $userEntity->getState()
        );
    }

    /**
     * @param UserEntity $user
     */
    public function delete(UserEntity $user): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $user->getIdentifier(),
            ]
        );
    }

    /**
     * @param UserEntity $user
     */
    public function update(UserEntity $user): void
    {
        $stmt = sprintf(
            "UPDATE %s SET claims = :claims, updated_at = :updated_at, created_at = :created_at WHERE id = :id",
            $this->getTableName()
        );

        $this->database->write(
            $stmt,
            $user->getState()
        );
    }
}

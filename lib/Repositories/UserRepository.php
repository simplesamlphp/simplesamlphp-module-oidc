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

use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
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
     * @return \SimpleSAML\Module\oidc\Entity\UserEntity|null
     */
    public function getUserEntityByIdentifier($identifier)
    {
        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $identifier,
            ]
        );

        if (!$rows = $stmt->fetchAll()) {
            return null;
        }

        return UserEntity::fromState(current($rows));
    }

    /**
     * {@inheritdoc}
     */
    public function getUserEntityByUserCredentials(
        $username,
        $password,
        $grantType,
        OAuth2ClientEntityInterface $clientEntity
    ) {
        throw new \Exception('Not supported');
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
     * @param \SimpleSAML\Module\oidc\Entity\UserEntity $userEntity
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
     * @param \SimpleSAML\Module\oidc\Entity\UserEntity $userEntity
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

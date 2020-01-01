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

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;

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
     * @return \SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity|null
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
        ClientEntityInterface $clientEntity
    ) {
        throw new \Exception('Not supported');
    }

    public function add(UserEntity $userEntity): void
    {
        $this->database->write(
            "INSERT INTO {$this->getTableName()} (id, claims, updated_at, created_at) VALUES (:id, :claims, :updated_at, :created_at)",
            $userEntity->getState()
        );
    }

    /**
     * @param \SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity $userEntity
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
     * @param \SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity $userEntity
     */
    public function update(UserEntity $user): void
    {
        $this->database->write(
            "UPDATE {$this->getTableName()} SET claims = :claims, updated_at = :updated_at, created_at = :created_at WHERE id = :id",
            $user->getState()
        );
    }
}

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
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\ScopeEntity;

class ScopeRepository extends AbstractDatabaseRepository implements ScopeRepositoryInterface
{
    protected static $standardClaims = [
        'openid' => [
            'description' => 'openid',
        ],
        'profile' => [
            'description' => 'profile',
        ],
        'email' => [
            'description' => 'email',
        ],
        'address' => [
            'description' => 'address',
        ],
        'phone' => [
            'description' => 'phone',
        ],
    ];

    /**
     * @codeCoverageIgnore
     */
    public function getTableName()
    {
        return null;
    }

    public function findAll()
    {
        return array_merge(static::$standardClaims, $this->config->getArray('scopes'));
    }

    /**
     * {@inheritdoc}
     */
    public function getScopeEntityByIdentifier($identifier)
    {
        $scopes = array_merge(static::$standardClaims, $this->config->getArray('scopes'));

        if (false === array_key_exists($identifier, $scopes)) {
            return null;
        }

        $scope = $scopes[$identifier];
        $description = $scope['description'] ?? null;
        $icon = $scope['icon'] ?? null;
        $attributes = $scope['attributes'] ?? [];

        $scope = ScopeEntity::fromData(
            $identifier,
            $description,
            $icon,
            $attributes
        );

        return $scope;
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeScopes(
        array $scopes,
        $grantType,
        ClientEntityInterface $clientEntity,
        $userIdentifier = null
    ) {
        return array_filter($scopes, function (ScopeEntityInterface $scope) use ($clientEntity) {
            return \in_array($scope->getIdentifier(), $clientEntity->getScopes(), true);
        });
    }
}

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

use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;

use function array_key_exists;
use function in_array;

class ScopeRepository extends AbstractDatabaseRepository implements ScopeRepositoryInterface
{
    public function getTableName(): ?string
    {
        return null;
    }

    /**
     * {@inheritdoc}
     * @throws \Exception
     */
    public function getScopeEntityByIdentifier($identifier): ScopeEntity|ScopeEntityInterface|null
    {
        $scopes = $this->moduleConfig->getOpenIDScopes();

        if (false === array_key_exists($identifier, $scopes)) {
            return null;
        }

        /** @var array $scope */
        $scope = $scopes[$identifier];
        /** @var ?string $description */
        $description = $scope['description'] ?? null;
        /** @var ?string $icon */
        $icon = $scope['icon'] ?? null;
        /** @var string[] $claims */
        $claims = $scope['claims'] ?? [];

        return ScopeEntity::fromData(
            $identifier,
            $description,
            $icon,
            $claims,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeScopes(
        array $scopes,
        $grantType,
        OAuth2ClientEntityInterface $clientEntity,
        $userIdentifier = null,
    ): array {
        if (!$clientEntity instanceof ClientEntity) {
            return [];
        }

        return array_filter(
            $scopes,
            fn(ScopeEntityInterface $scope) => in_array($scope->getIdentifier(), $clientEntity->getScopes(), true),
        );
    }
}

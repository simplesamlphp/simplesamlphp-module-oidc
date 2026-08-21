<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ScopeEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;

use function array_key_exists;
use function in_array;

class ScopeRepository implements ScopeRepositoryInterface
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly ScopeEntityFactory $scopeEntityFactory,
    ) {
    }

    /**
     * {@inheritdoc}
     * @throws \Exception
     */
    public function getScopeEntityByIdentifier(string $identifier): ScopeEntity|ScopeEntityInterface|null
    {
        $scopes = $this->moduleConfig->getScopes();

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

        return $this->scopeEntityFactory->fromData(
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
        string $grantType,
        OAuth2ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
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

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

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use PDO;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

class ClientRepository extends AbstractDatabaseRepository implements ClientRepositoryInterface
{
    public function __construct(
        ModuleConfig $moduleConfig,
        Database $database,
        ?ProtocolCache $protocolCache,
        protected readonly ClientEntityFactory $clientEntityFactory,
    ) {
        parent::__construct($moduleConfig, $database, $protocolCache);
    }

    final public const TABLE_NAME = 'oidc_client';

    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    /**
     * {@inheritdoc}
     * @throws \JsonException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function getClientEntity($clientIdentifier)
    {
        $client = $this->findById($clientIdentifier);

        if (!$client instanceof ClientEntityInterface) {
            return null;
        }

        if ($client->isExpired()) {
            return null;
        }

        if (false === $client->isEnabled()) {
            return null;
        }

        return $client;
    }

    /**
     * @inheritDoc
     * @throws \JsonException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function validateClient($clientIdentifier, $clientSecret, $grantType): bool
    {
        $client = $this->getClientEntity($clientIdentifier);

        if (!$client instanceof ClientEntity) {
            return false;
        }

        if ($client->isConfidential()) {
            return hash_equals($client->getSecret(), (string) $clientSecret);
        }

        return true;
    }

    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function findById(string $clientIdentifier, ?string $owner = null): ?ClientEntityInterface
    {
        /** @var ?array $cachedState */
        $cachedState = $this->protocolCache?->get(null, $this->getCacheKey($clientIdentifier));

        if (is_array($cachedState)) {
            return $this->clientEntityFactory->fromState($cachedState);
        }

        /**
         * @var string $query
         * @var array $params
         */
        [$query, $params] = $this->addOwnerWhereClause(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $clientIdentifier,
            ],
            $owner,
        );

        $stmt = $this->database->read($query, $params);

        if (empty($rows = $stmt->fetchAll())) {
            return null;
        }

        $row = current($rows);

        // @codeCoverageIgnoreStart
        if (!is_array($row)) {
            return null;
        }
        // @codeCoverageIgnoreEnd

        $clientEntity = $this->clientEntityFactory->fromState($row);

        $this->protocolCache?->set(
            $clientEntity->getState(),
            $this->moduleConfig->getProtocolClientEntityCacheDuration(),
            $this->getCacheKey($clientEntity->getIdentifier()),
        );

        return $clientEntity;
    }

    public function findByEntityIdentifier(string $entityIdentifier, ?string $owner = null): ?ClientEntityInterface
    {
        /** @var ?array $cachedState */
        $cachedState = $this->protocolCache?->get(null, $this->getCacheKey($entityIdentifier));

        if (is_array($cachedState)) {
            return $this->clientEntityFactory->fromState($cachedState);
        }

        /**
         * @var string $query
         * @var array $params
         */
        [$query, $params] = $this->addOwnerWhereClause(
            <<<EOS
            SELECT * FROM {$this->getTableName()}
            WHERE
                entity_identifier = :entity_identifier
            EOS,
            [
                'entity_identifier' => $entityIdentifier,
            ],
            $owner,
        );

        $stmt = $this->database->read($query, $params);

        if (empty($rows = $stmt->fetchAll())) {
            return null;
        }

        $row = current($rows);

        // @codeCoverageIgnoreStart
        if (!is_array($row)) {
            return null;
        }
        // @codeCoverageIgnoreEnd

        $clientEntity = $this->clientEntityFactory->fromState($row);

        $this->protocolCache?->set(
            $clientEntity->getState(),
            $this->moduleConfig->getProtocolClientEntityCacheDuration(),
            $this->getCacheKey($entityIdentifier),
        );

        return $clientEntity;
    }

    public function findFederatedByEntityIdentifier(
        string $entityIdentifier,
        ?string $owner = null,
    ): ?ClientEntityInterface {
        $clientEntity = $this->findByEntityIdentifier($entityIdentifier, $owner);

        if (is_null($clientEntity)) {
            return null;
        }

        if (
            is_null($clientEntity->getEntityIdentifier()) ||
            (! $clientEntity->isEnabled()) ||
            (! $clientEntity->isFederated()) ||
            (!is_array($clientEntity->getFederationJwks())) ||
            $clientEntity->isExpired()
        ) {
            return null;
        }

        return $clientEntity;
    }

    private function addOwnerWhereClause(string $query, array $params, ?string $owner = null): array
    {
        if (isset($owner)) {
            $params['ownerFilter'] = $owner;
            if (stripos($query, ' where ') > 0) {
                $query .= ' AND owner = :ownerFilter';
            } else {
                $query .= ' WHERE owner = :ownerFilter';
            }
        }
        return [$query, $params];
    }

    /**
     * @return \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface[]
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function findAll(?string $owner = null): array
    {
        /**
         * @var string $query
         * @var array $params
         */
        [$query, $params] = $this->addOwnerWhereClause(
            "SELECT * FROM {$this->getTableName()}",
            [],
            $owner,
        );
        $stmt = $this->database->read(
            "$query ORDER BY name ASC",
            $params,
        );

        $clients = [];

        /** @var array $state */
        foreach ($stmt->fetchAll() as $state) {
            $clients[] = $this->clientEntityFactory->fromState($state);
        }

        return $clients;
    }

    /**
     * @return \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface[]
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function findAllFederated(?string $owner = null): array
    {
        /**
         * @var string $query
         * @var array $params
         */
        [$query, $params] = $this->addOwnerWhereClause(
            <<<EOS
            SELECT * FROM {$this->getTableName()}
            WHERE
                entity_identifier IS NOT NULL AND
                federation_jwks IS NOT NULL AND
                is_enabled = :is_enabled AND
                is_federated = :is_federated
            EOS,
            [
                'is_enabled' => [true, PDO::PARAM_BOOL],
                'is_federated' => [true, PDO::PARAM_BOOL],
            ],
            $owner,
        );
        $stmt = $this->database->read(
            "$query ORDER BY name ASC",
            $params,
        );

        $clients = [];

        /** @var array $state */
        foreach ($stmt->fetchAll() as $state) {
            $clients[] = $this->clientEntityFactory->fromState($state);
        }

        return $clients;
    }

    /**
     * @return array{
     *   numPages: int,
     *   currentPage: int,
     *   items: \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface[]
     * }
     * @throws \Exception
     */
    public function findPaginated(int $page = 1, string $query = '', ?string $owner = null): array
    {
        $query = mb_substr($query, 0, 2000);
        $total = $this->count($query, $owner);
        $limit = $this->getItemsPerPage();
        $numPages = $this->calculateNumOfPages($total, $limit);
        $page = $this->calculateCurrentPage($page, $numPages);
        $offset = $this->calculateOffset($page, $limit);

        /**
         * @var string $sqlQuery
         * @var array $params
         */
        [$sqlQuery, $params] = $this->addOwnerWhereClause(
            "SELECT * FROM {$this->getTableName()} WHERE name LIKE :name",
            ['name' => '%' . $query . '%'],
            $owner,
        );
        $stmt = $this->database->read(
            $sqlQuery . " ORDER BY name ASC LIMIT $limit OFFSET $offset",
            $params,
        );

        $clients = array_map(fn(array $state) => $this->clientEntityFactory->fromState($state), $stmt->fetchAll());

        return [
            'numPages' => $numPages,
            'currentPage' => $page,
            'items' => $clients,
        ];
    }

    public function add(ClientEntityInterface $client): void
    {
        $stmt = sprintf(
            <<<EOS
            INSERT INTO %s (
                id,
                secret,
                name,
                description,
                auth_source,
                redirect_uri,
                scopes,
                is_enabled,
                is_confidential,
                owner,
                post_logout_redirect_uri,
                backchannel_logout_uri,
                entity_identifier,
                client_registration_types,
                federation_jwks,
                jwks,
                jwks_uri,
                signed_jwks_uri,
                registration_type,
                updated_at,
                created_at,
                expires_at,
                is_federated
            )
            VALUES (
                :id,
                :secret,
                :name,
                :description,
                :auth_source,
                :redirect_uri,
                :scopes,
                :is_enabled,
                :is_confidential,
                :owner,
                :post_logout_redirect_uri,
                :backchannel_logout_uri,
                :entity_identifier,
                :client_registration_types,
                :federation_jwks,
                :jwks,
                :jwks_uri,
                :signed_jwks_uri,
                :registration_type,
                :updated_at,
                :created_at,
                :expires_at,
                :is_federated
            )
EOS
            ,
            $this->getTableName(),
        );
        $this->database->write(
            $stmt,
            $this->preparePdoState($client->getState()),
        );

        $this->protocolCache?->set(
            $client->getState(),
            $this->moduleConfig->getProtocolClientEntityCacheDuration(),
            $this->getCacheKey($client->getIdentifier()),
        );
        if (($entityIdentifier = $client->getEntityIdentifier()) !== null) {
            $this->protocolCache?->set(
                $client->getState(),
                $this->moduleConfig->getProtocolClientEntityCacheDuration(),
                $this->getCacheKey($entityIdentifier),
            );
        }
    }

    public function delete(ClientEntityInterface $client, ?string $owner = null): void
    {
        /**
         * @var string $sqlQuery
         * @var array $params
         */
        [$sqlQuery, $params] = $this->addOwnerWhereClause(
            "DELETE FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $client->getIdentifier(),
            ],
            $owner,
        );
        $this->database->write($sqlQuery, $params);

        $this->protocolCache?->delete($this->getCacheKey($client->getIdentifier()));
        if (($entityIdentifier = $client->getEntityIdentifier()) !== null) {
            $this->protocolCache?->delete($this->getCacheKey($entityIdentifier));
        }
    }

    public function update(ClientEntityInterface $client, ?string $owner = null): void
    {
        $stmt = sprintf(
            <<<EOF
            UPDATE %s SET
                secret = :secret,
                name = :name,
                description = :description,
                auth_source = :auth_source,
                redirect_uri = :redirect_uri,
                scopes = :scopes,
                is_enabled = :is_enabled,
                is_confidential = :is_confidential,
                owner = :owner,
                post_logout_redirect_uri = :post_logout_redirect_uri,
                backchannel_logout_uri = :backchannel_logout_uri,
                entity_identifier = :entity_identifier,
                client_registration_types = :client_registration_types,
                federation_jwks = :federation_jwks,
                jwks = :jwks,
                jwks_uri = :jwks_uri,
                signed_jwks_uri = :signed_jwks_uri,
                registration_type = :registration_type,
                updated_at = :updated_at,
                created_at = :created_at,
                expires_at = :expires_at,
                is_federated = :is_federated
            WHERE id = :id
EOF
            ,
            $this->getTableName(),
        );

        /**
         * @var string $sqlQuery
         * @var array $params
         */
        [$sqlQuery, $params] = $this->addOwnerWhereClause(
            $stmt,
            $this->preparePdoState($client->getState()),
            $owner,
        );
        $this->database->write(
            $sqlQuery,
            $params,
        );

        $this->protocolCache?->set(
            $client->getState(),
            $this->moduleConfig->getProtocolClientEntityCacheDuration(),
            $this->getCacheKey($client->getIdentifier()),
        );
        if (($entityIdentifier = $client->getEntityIdentifier()) !== null) {
            $this->protocolCache?->set(
                $client->getState(),
                $this->moduleConfig->getProtocolClientEntityCacheDuration(),
                $this->getCacheKey($entityIdentifier),
            );
        }
    }

    private function count(string $query, ?string $owner): int
    {
        /**
         * @var string $sqlQuery
         * @var array $params
         */
        [$sqlQuery, $params] = $this->addOwnerWhereClause(
            "SELECT COUNT(id) FROM {$this->getTableName()} WHERE name LIKE :name",
            ['name' => '%' . $query . '%'],
            $owner,
        );
        $stmt = $this->database->read(
            $sqlQuery,
            $params,
        );
        $stmt->execute();

        return (int) $stmt->fetchColumn();
    }

    /**
     * @throws \Exception
     */
    private function getItemsPerPage(): int
    {
        return $this->moduleConfig->config()
            ->getOptionalIntegerRange(ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE, 1, 100, 20);
    }

    private function calculateNumOfPages(int $total, int $limit): int
    {
        $numPages = (int)ceil($total / $limit);

        return max($numPages, 1);
    }

    private function calculateCurrentPage(int $page, int $numPages): int
    {
        if ($page > $numPages) {
            return $numPages;
        }

        if ($page < 1) {
            return 1;
        }

        return $page;
    }

    private function calculateOffset(int $page, int $limit): float|int
    {
        return ($page - 1) * $limit;
    }

    protected function preparePdoState(array $state): array
    {
        $isEnabled = (bool)($state[ClientEntity::KEY_IS_ENABLED] ?? false);
        $isConfidential = (bool)($state[ClientEntity::KEY_IS_CONFIDENTIAL] ?? false);
        $isFederated = (bool)($state[ClientEntity::KEY_IS_FEDERATED] ?? false);

        $state[ClientEntity::KEY_IS_ENABLED] = [$isEnabled, PDO::PARAM_BOOL];
        $state[ClientEntity::KEY_IS_CONFIDENTIAL] = [$isConfidential, PDO::PARAM_BOOL];
        $state[ClientEntity::KEY_IS_FEDERATED] = [$isFederated, PDO::PARAM_BOOL];

        return $state;
    }
}

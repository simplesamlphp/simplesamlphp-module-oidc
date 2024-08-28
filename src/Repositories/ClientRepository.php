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

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ModuleConfig;

class ClientRepository extends AbstractDatabaseRepository implements ClientRepositoryInterface
{
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

        if (false === $client->isEnabled()) {
            throw OAuthServerException::accessDenied('Client is disabled');
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

        if (!is_array($row)) {
            return null;
        }

        return ClientEntity::fromState($row);
    }

    public function findByEntityIdentifier(string $entityIdentifier, ?string $owner = null): ?ClientEntityInterface
    {
        /**
         * @var string $query
         * @var array $params
         */
        [$query, $params] = $this->addOwnerWhereClause(
            "SELECT * FROM {$this->getTableName()} WHERE entity_identifier = :entity_identifier",
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

        if (!is_array($row)) {
            return null;
        }

        return ClientEntity::fromState($row);
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
            $clients[] = ClientEntity::fromState($state);
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

        $clients = array_map(fn(array $state) => ClientEntity::fromState($state), $stmt->fetchAll());

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
                protocol_jwks
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
                :protocol_jwks
            )
EOS
            ,
            $this->getTableName(),
        );
        $this->database->write(
            $stmt,
            $client->getState(),
        );
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
                protocol_jwks = :protocol_jwks
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
            $client->getState(),
            $owner,
        );
        $this->database->write(
            $sqlQuery,
            $params,
        );
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
        return $this->config
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
}

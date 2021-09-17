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

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;

class ClientRepository extends AbstractDatabaseRepository implements ClientRepositoryInterface
{
    public const TABLE_NAME = 'oidc_client';

    /**
     * @return string
     */
    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    /**
     * {@inheritdoc}
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
     */
    public function validateClient($clientIdentifier, $clientSecret, $grantType)
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
     * @param string $clientIdentifier
     * @param ?string $owner restrict lookup to this owner
     * @return ClientEntityInterface|null
     */
    public function findById(string $clientIdentifier, ?string $owner = null): ?ClientEntityInterface
    {
        list($query, $params) = $this->addOwnerWhereClause(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $clientIdentifier,
            ],
            $owner
        );
        $stmt = $this->database->read($query, $params);

        if (!$rows = $stmt->fetchAll()) {
            return null;
        }

        return ClientEntity::fromState(current($rows));
    }

    private function addOwnerWhereClause(string $query, array $params, ?string $owner = null)
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
     * @return ClientEntityInterface[]
     */
    public function findAll(?string $owner = null): array
    {
        list($query, $params) = $this->addOwnerWhereClause(
            "SELECT * FROM {$this->getTableName()}",
            [],
            $owner
        );
        $stmt = $this->database->read(
            "$query ORDER BY name ASC",
            $params
        );

        $clients = [];

        foreach ($stmt->fetchAll() as $state) {
            $clients[] = ClientEntity::fromState($state);
        }

        return $clients;
    }

    /**
     * @param int $page
     * @param string $query
     *
     * @return array{numPages: int, currentPage: int, items: ClientEntityInterface[]}
     */
    public function findPaginated(int $page = 1, string $query = '', ?string $owner = null): array
    {
        $query = mb_substr($query, 0, 2000);
        $total = $this->count($query, $owner);
        $limit = $this->getItemsPerPage();
        $numPages = $this->calculateNumOfPages($total, $limit);
        $page = $this->calculateCurrentPage($page, $numPages);
        $offset = $this->calculateOffset($page, $limit);
        list($sqlQuery, $params) = $this->addOwnerWhereClause(
            "SELECT * FROM {$this->getTableName()} WHERE name LIKE :name",
            ['name' => '%' . $query . '%'],
            $owner
        );
        $stmt = $this->database->read(
            $sqlQuery . " ORDER BY name ASC LIMIT {$limit} OFFSET {$offset}",
            $params
        );

        $clients = array_map(function ($state) {
            return ClientEntity::fromState($state);
        }, $stmt->fetchAll());

        return [
            'numPages' => $numPages,
            'currentPage' => $page,
            'items' => $clients
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
                backchannel_logout_uri
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
                :backchannel_logout_uri
            )
EOS
            ,
            $this->getTableName()
        );
        $this->database->write(
            $stmt,
            $client->getState()
        );
    }

    public function delete(ClientEntityInterface $client, ?string $owner = null): void
    {
        list($sqlQuery, $params) = $this->addOwnerWhereClause(
            "DELETE FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $client->getIdentifier(),
            ],
            $owner
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
                backchannel_logout_uri = :backchannel_logout_uri
            WHERE id = :id
EOF
            ,
            $this->getTableName()
        );
        list($sqlQuery, $params) = $this->addOwnerWhereClause(
            $stmt,
            $client->getState(),
            $owner
        );
        $this->database->write(
            $sqlQuery,
            $params
        );
    }

    private function count(string $query, ?string $owner): int
    {
        list($sqlQuery, $params) = $this->addOwnerWhereClause(
            "SELECT COUNT(id) FROM {$this->getTableName()} WHERE name LIKE :name",
            ['name' => '%' . $query . '%'],
            $owner
        );
        $stmt = $this->database->read(
            $sqlQuery,
            $params
        );
        $stmt->execute();

        return (int) $stmt->fetchColumn(0);
    }

    private function getItemsPerPage(): int
    {
        return $this->config->getIntegerRange('items_per_page', 1, 100, 20);
    }

    /**
     * @param int $total
     * @param int $limit
     * @return int
     */
    private function calculateNumOfPages(int $total, int $limit): int
    {
        $numPages = (int)ceil($total / $limit);

        return $numPages < 1 ? 1 : $numPages;
    }

    /**
     * @param int $page
     * @param int $numPages
     * @return int
     */
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


    /**
     * @param int $page
     * @param int $limit
     * @return float|int
     */
    private function calculateOffset(int $page, int $limit)
    {
        return ($page - 1) * $limit;
    }
}

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

use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;

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
     * @return ClientEntityInterface|null
     */
    public function findById(string $clientIdentifier): ?ClientEntityInterface
    {
        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $clientIdentifier,
            ]
        );

        if (!$rows = $stmt->fetchAll()) {
            return null;
        }

        return ClientEntity::fromState(current($rows));
    }

    /**
     * @return ClientEntityInterface[]
     */
    public function findAll(): array
    {
        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} ORDER BY name ASC"
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
    public function findPaginated(int $page = 1, string $query = ''): array
    {
        $query = mb_substr($query, 0, 2000);
        $total = $this->count($query);
        $limit = $this->getItemsPerPage();
        $numPages = $this->calculateNumOfPages($total, $limit);
        $page = $this->calculateCurrentPage($page, $numPages);
        $offset = $this->calculateOffset($page, $limit);

        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} WHERE name LIKE :name ORDER BY name ASC LIMIT {$limit} OFFSET {$offset}",
            ['name' => '%' . $query . '%']
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
                 is_confidential
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
                :is_confidential
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

    public function delete(ClientEntityInterface $client): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $client->getIdentifier(),
            ]
        );
    }

    public function update(ClientEntityInterface $client): void
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
                is_confidential = :is_confidential
            WHERE id = :id
EOF
            ,
            $this->getTableName()
        );

        $this->database->write(
            $stmt,
            $client->getState()
        );
    }

    private function count(string $query): int
    {
        $stmt = $this->database->read(
            "SELECT COUNT(id) FROM {$this->getTableName()} WHERE name LIKE :name",
            ['name' => '%' . $query . '%']
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

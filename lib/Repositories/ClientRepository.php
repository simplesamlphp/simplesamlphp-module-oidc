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

        if (!$client instanceof ClientEntity) {
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
     */
    public function findById($clientIdentifier): ?ClientEntity
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
     * @return \SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity[]
     */
    public function findAll()
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
     *
     * @return array{numPages: int, currentPage: int, items: ClientEntityInterface[]}
     */
    public function findPaginated(int $page = 1): array
    {
        $total = $this->count();
        $limit = $this->getItemsPerPage();
        $numPages = (int)ceil($total / $limit);

        $page = $page > $numPages ? $numPages : $page;
        $page = $page < 1 ? 1 : $page;

        $offset = ($page - 1) * $limit;

        $stmt = $this->database->read(
            "SELECT * FROM {$this->getTableName()} ORDER BY name ASC LIMIT {$limit} OFFSET {$offset}"
        );

        /** @var ClientEntityInterface[] $clients */
        $clients = [];

        foreach ($stmt->fetchAll() as $state) {
            $clients[] = ClientEntity::fromState($state);
        }

        return [
            'numPages' => $numPages,
            'currentPage' => $page,
            'items' => $clients
        ];
    }

    public function add(ClientEntity $client): void
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

    public function delete(ClientEntity $client): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE id = :id",
            [
                'id' => $client->getIdentifier(),
            ]
        );
    }

    public function update(ClientEntity $client): void
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

    private function count(): int
    {
        $stmt = $this->database->read(
            "SELECT COUNT(id) FROM {$this->getTableName()}"
        );
        $stmt->execute();

        return (int) $stmt->fetchColumn(0);
    }

    private function getItemsPerPage(): int
    {
        $itemsPerPage = $this->config->getInteger('items_per_page', 20);

        return $itemsPerPage < 0 ? 20 : $itemsPerPage;
    }
}

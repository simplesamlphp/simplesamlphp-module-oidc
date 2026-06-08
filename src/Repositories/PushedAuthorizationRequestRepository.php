<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2026 by the Spanish Research and Academic Network.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Repositories;

use DateTimeImmutable;
use PDO;
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;

class PushedAuthorizationRequestRepository extends AbstractDatabaseRepository
{
    final public const string TABLE_NAME = 'oidc_par';

    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    /**
     * Persist the PAR entity in the database.
     *
     * @throws \JsonException
     */
    public function persist(PushedAuthorizationRequestEntity $entity): void
    {
        $state = $entity->getState();

        $stmt = "INSERT INTO {$this->getTableName()} (request_uri, client_id, parameters, expires_at, is_consumed) " .
        "VALUES (:request_uri, :client_id, :parameters, :expires_at, :is_consumed)";

        $this->database->write($stmt, [
            'request_uri' => $state['request_uri'],
            'client_id' => $state['client_id'],
            'parameters' => $state['parameters'],
            'expires_at' => $state['expires_at'],
            'is_consumed' => $state['is_consumed'] ? 1 : 0,
        ]);
    }

    /**
     * Find PAR entity by request_uri.
     *
     * @throws \Exception
     */
    public function findByRequestUri(string $requestUri): ?PushedAuthorizationRequestEntity
    {
        $stmt = $this->database->read(
            "SELECT client_id, parameters, expires_at, is_consumed " .
            "FROM {$this->getTableName()} WHERE request_uri = :request_uri LIMIT 1",
            ['request_uri' => $requestUri],
        );

        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            return null;
        }

        /** @psalm-suppress MixedAssignment */
        $decoded = json_decode((string)$row['parameters'], true, 512, JSON_THROW_ON_ERROR);
        $parameters = is_array($decoded) ? $decoded : [];

        return new PushedAuthorizationRequestEntity(
            requestUri: $requestUri,
            clientId: (string)$row['client_id'],
            parameters: $parameters,
            expiresAt: new DateTimeImmutable((string)$row['expires_at']),
            isConsumed: (bool)$row['is_consumed'],
        );
    }

    /**
     * Mark a PAR record as consumed.
     */
    public function consume(string $requestUri): void
    {
        $stmt = "UPDATE {$this->getTableName()} SET is_consumed = 1 WHERE request_uri = :request_uri";
        $this->database->write($stmt, ['request_uri' => $requestUri]);
    }

    /**
     * Delete expired PAR records.
     */
    public function deleteExpired(DateTimeImmutable $now): int
    {
        $stmt = "DELETE FROM {$this->getTableName()} WHERE expires_at < :now";
        $result = $this->database->write($stmt, ['now' => $now->format('Y-m-d H:i:s')]);
        return is_int($result) ? $result : 0;
    }
}

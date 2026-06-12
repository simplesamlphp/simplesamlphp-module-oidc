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

use PDO;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

class PushedAuthorizationRequestRepository extends AbstractDatabaseRepository
{
    final public const string TABLE_NAME = 'oidc_par';

    public function __construct(
        ModuleConfig $moduleConfig,
        Database $database,
        ?ProtocolCache $protocolCache,
        protected readonly PushedAuthorizationRequestEntityFactory $pushedAuthorizationRequestEntityFactory,
        protected readonly Helpers $helpers,
    ) {
        parent::__construct($moduleConfig, $database, $protocolCache);
    }

    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    /**
     * Persist the Pushed Authorization Request entity in the database.
     *
     * @throws \JsonException
     */
    public function persist(PushedAuthorizationRequestEntity $entity): void
    {
        $stmt = "INSERT INTO {$this->getTableName()} (request_uri, client_id, parameters, expires_at, is_consumed) " .
        "VALUES (:request_uri, :client_id, :parameters, :expires_at, :is_consumed)";

        $params = $entity->getState();
        $params['is_consumed'] = (int)$params['is_consumed'];

        $this->database->write($stmt, $params);

        $this->protocolCache?->set(
            $entity->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime($entity->getExpiresAt()->getTimestamp()),
            $this->getCacheKey($entity->getRequestUri()),
        );
    }

    /**
     * Find Pushed Authorization Request entity by request_uri.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \JsonException
     * @throws \Exception
     */
    public function find(string $requestUri): ?PushedAuthorizationRequestEntity
    {
        /** @var ?array $state */
        $state = $this->protocolCache?->get(null, $this->getCacheKey($requestUri));

        if (!is_array($state)) {
            $stmt = $this->database->read(
                "SELECT request_uri, client_id, parameters, expires_at, is_consumed " .
                "FROM {$this->getTableName()} WHERE request_uri = :request_uri",
                ['request_uri' => $requestUri],
            );

            if (!is_array($state = $stmt->fetch(PDO::FETCH_ASSOC))) {
                return null;
            }
        }

        $entity = $this->pushedAuthorizationRequestEntityFactory->fromState($state);

        $this->protocolCache?->set(
            $entity->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime($entity->getExpiresAt()->getTimestamp()),
            $this->getCacheKey($entity->getRequestUri()),
        );

        return $entity;
    }

    /**
     * Find Pushed Authorization Request entity which is not consumed nor expired.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \JsonException
     * @throws \Exception
     */
    public function findValid(string $requestUri): ?PushedAuthorizationRequestEntity
    {
        $entity = $this->find($requestUri);

        if ($entity === null) {
            return null;
        }

        if ($entity->isConsumed()) {
            return null;
        }

        if ($entity->isExpired($this->helpers->dateTime()->getUtc())) {
            return null;
        }

        return $entity;
    }

    /**
     * Mark the Pushed Authorization Request as consumed (one-time use). Atomic,
     * so it can be used as a replay guard: returns true only if this call was
     * the one that consumed it. Note that the database is the source of truth
     * for consumption (the protocol cache is only a read accelerator), so a
     * stale cached entry can never enable a replay.
     */
    public function consume(string $requestUri): bool
    {
        $stmt = "UPDATE {$this->getTableName()} SET is_consumed = 1 " .
        "WHERE request_uri = :request_uri AND is_consumed = 0";

        $affected = $this->database->write($stmt, ['request_uri' => $requestUri]);

        // Invalidate the cached entry, so subsequent finds reflect the consumed state.
        $this->protocolCache?->delete($this->getCacheKey($requestUri));

        return is_int($affected) && $affected > 0;
    }

    /**
     * Delete expired Pushed Authorization Request records.
     */
    public function removeExpired(): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE expires_at < :now",
            ['now' => $this->helpers->dateTime()->getUtc()->format(DateFormatsEnum::DB_DATETIME->value)],
        );
    }
}

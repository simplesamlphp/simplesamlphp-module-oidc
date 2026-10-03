<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use PDO;

/**
 * Every query here reads the database primary rather than a secondary, which may not have the origins of a client
 * changed moments earlier yet: a browser client may make a CORS request as soon as its origin is allowed, an origin
 * removed from a client is to be refused from then on, and the administrator's client form is filled in with the
 * origins read here, which saving it writes back.
 *
 * For the same reason, a change of a client's origins clears the answers has() cached for every origin it touches,
 * the removed ones included. That is done once the rows are written, and also when writing them fails part way: a
 * lookup made in between would put the answer from before the change back in the cache.
 */
class AllowedOriginRepository extends AbstractDatabaseRepository
{
    final public const string TABLE_NAME = 'oidc_allowed_origin';


    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }


    /**
     * @param string[] $origins
     */
    public function set(string $clientId, array $origins): void
    {
        $origins = array_values(array_unique(array_filter($origins)));
        $previousOrigins = $this->get($clientId);

        try {
            $this->deleteRows($clientId);
            $this->insertRows($clientId, $origins);
        } finally {
            $this->clearCache(array_unique(array_merge($previousOrigins, $origins)));
        }
    }


    public function delete(string $clientId): void
    {
        $previousOrigins = $this->get($clientId);

        try {
            $this->deleteRows($clientId);
        } finally {
            $this->clearCache($previousOrigins);
        }
    }


    public function get(string $clientId): array
    {
        $stmt = $this->database->readPrimary(
            "SELECT origin FROM {$this->getTableName()} WHERE client_id = :client_id",
            ['client_id' => $clientId],
        );

        return $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
    }


    public function has(string $origin): bool
    {
        // We only cache this method since it is used in authentication flow.
        $has = $this->protocolCache?->get(null, $this->getCacheKey($origin));

        if ($has !== null) {
            return (bool) $has;
        }

        $stmt = $this->database->readPrimary(
            "SELECT origin FROM {$this->getTableName()} WHERE origin = :origin LIMIT 1",
            ['origin' => $origin],
        );

        $has = (bool) count($stmt->fetchAll(PDO::FETCH_COLUMN, 0));

        $this->protocolCache?->set(
            $has,
            $this->moduleConfig->getProtocolClientEntityCacheDuration(),
            $this->getCacheKey($origin),
        );

        return $has;
    }


    /**
     * Clear the answers has() cached for the given origins. A client's origins may also leave without this
     * repository deleting them, the foreign key taking them with a deleted client.
     */
    public function clearCache(array $origins): void
    {
        /** @var string $origin */
        foreach ($origins as $origin) {
            $this->protocolCache?->delete($this->getCacheKey($origin));
        }
    }


    private function deleteRows(string $clientId): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE client_id = :client_id",
            ['client_id' => $clientId],
        );
    }


    /**
     * @param list<string> $origins
     */
    private function insertRows(string $clientId, array $origins): void
    {
        if ($origins === []) {
            return;
        }

        $stmt = "INSERT INTO {$this->getTableName()} (client_id, origin) VALUES ";

        $params = [];
        foreach ($origins as $idx => $origin) {
            if ($idx > 0) {
                $stmt .= ',';
            }
            $paramClientPlaceholder = 'client_id_' . $idx;
            $paramOriginPlaceholder = 'origin_' . $idx;
            $params[$paramClientPlaceholder] = $clientId;
            $params[$paramOriginPlaceholder] = $origin;
            $stmt .= "(:$paramClientPlaceholder, :$paramOriginPlaceholder)";
        }

        $this->database->write($stmt, $params);
    }
}

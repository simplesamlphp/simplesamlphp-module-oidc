<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

/**
 * Storage for Status Lists themselves, as distinct from the entries they hold.
 *
 * Which read is used where is a correctness decision rather than a performance one. A secondary may lag
 * the primary, so anything driving a decision -- selecting a list to allocate into, observing the
 * published content hash before replacing it, deciding whether a list is still active -- reads the
 * primary. The one exception is the endpoint's single-row fetch of an already published token: serving
 * a token one replica-lag interval old is bounded by the token's own `ttl`, which is measured in hours,
 * and that read is the one which actually has to scale.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Repositories\StatusListRepositoryTest
 */
class StatusListRepository extends AbstractDatabaseRepository
{
    final public const string TABLE_NAME = 'oidc_status_list';

    public function __construct(
        ModuleConfig $moduleConfig,
        Database $database,
        ?ProtocolCache $protocolCache,
        protected readonly Helpers $helpers,
    ) {
        parent::__construct($moduleConfig, $database, $protocolCache);
    }

    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    /**
     * Reads a list for the purpose of serving it.
     *
     * Deliberately a secondary read: this is the endpoint's hot path, and a token which is one
     * replica-lag interval stale is well inside the staleness the `ttl` claim already sanctions.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function findById(string $id): ?StatusListRecord
    {
        $statusList = $this->buildRecord(
            $this->database->read(
                "SELECT * FROM {$this->getTableName()} WHERE id = :id",
                ['id' => $id],
            )->fetchAll(),
        );

        if ($statusList instanceof StatusListRecord) {
            return $statusList;
        }

        // Not finding it is the one answer a secondary is not allowed to give on its own. Serving a
        // token a replication interval old is fine, and bounded by the token's own `ttl`; saying the
        // list does not exist is a 404 for a credential which was just issued and does. The extra read
        // only ever happens on this path, which is either that race or a genuinely unknown list.
        return $this->findByIdOnPrimary($id);
    }

    /**
     * Reads a list for the purpose of deciding something about it.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function findByIdOnPrimary(string $id): ?StatusListRecord
    {
        return $this->buildRecord(
            $this->readPrimary(
                "SELECT * FROM {$this->getTableName()} WHERE id = :id",
                ['id' => $id],
            ),
        );
    }

    /**
     * The lists new credentials of this pool may currently be allocated into.
     *
     * Filtering on the policy fingerprint and not merely on the pool is what keeps a settings change
     * from leaving lists created under the old policy eligible. During a signing key rotation in
     * particular, the issuer signs credentials with the current key while a list bound to the previous
     * one would still be selected, quietly breaking the profile which says the two are the same key.
     *
     * @return \SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord[]
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function findActiveForPolicy(string $poolId, string $policyFingerprint): array
    {
        $rows = $this->readPrimary(
            "SELECT * FROM {$this->getTableName()} " .
            'WHERE pool_id = :pool_id AND policy_fingerprint = :policy_fingerprint ' .
            'AND is_active = :is_active AND retired_at IS NULL',
            [
                'pool_id' => $poolId,
                'policy_fingerprint' => $policyFingerprint,
                'is_active' => [true, PDO::PARAM_BOOL],
            ],
        );

        $records = [];

        /** @var mixed $row */
        foreach ($rows as $row) {
            if (is_array($row)) {
                $records[] = StatusListRecord::fromRow($row);
            }
        }

        return $records;
    }

    /**
     * Lists of this pool which exist but are not open for allocation yet, because whichever request
     * created them is still seeding their entries.
     *
     * These are invisible to findActiveForPolicy() by design -- nothing may allocate into a list whose
     * indices do not all exist yet -- but they are not invisible to the decision of whether to start
     * another list. Without this, every request arriving during a seed would conclude the pool is empty
     * and start a list of its own, and the pool would end up with several sparse lists instead of one.
     * That costs herd privacy, which is the whole reason credentials share a list.
     *
     * @param \DateTimeImmutable $createdAfter Ignore anything older, which is taken to have been
     * abandoned by a request that died partway through seeding. Waiting on those would stall every
     * later request for nothing.
     * @param ?int $belowGeneration Restrict to generations below this one. Used by a request which has
     * just created a list to find out whether another request is already preparing an earlier one, in
     * which case its own is redundant.
     * @return \SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord[]
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function findBeingPreparedForPolicy(
        string $poolId,
        string $policyFingerprint,
        DateTimeImmutable $createdAfter,
        ?int $belowGeneration = null,
    ): array {
        $params = [
            'pool_id' => $poolId,
            'policy_fingerprint' => $policyFingerprint,
            'is_active' => [false, PDO::PARAM_BOOL],
            'created_after' => $this->nowForDatabase($createdAfter),
        ];

        $generationCondition = '';

        if ($belowGeneration !== null) {
            $generationCondition = ' AND generation < :below_generation';
            $params['below_generation'] = [$belowGeneration, PDO::PARAM_INT];
        }

        $rows = $this->readPrimary(
            "SELECT * FROM {$this->getTableName()} " .
            'WHERE pool_id = :pool_id AND policy_fingerprint = :policy_fingerprint ' .
            'AND is_active = :is_active AND deactivated_at IS NULL AND retired_at IS NULL ' .
            'AND created_at > :created_after' . $generationCondition,
            $params,
        );

        $records = [];

        /** @var mixed $row */
        foreach ($rows as $row) {
            if (is_array($row)) {
                $records[] = StatusListRecord::fromRow($row);
            }
        }

        return $records;
    }

    /**
     * Removes a list this request created and then decided not to use.
     *
     * Guarded so it can only ever remove one which was never opened, and so never one that a credential
     * could be pointing at: a list's URI is only handed out once it is open for allocation.
     *
     * The entries go first, explicitly, rather than through the foreign key. The constraint is declared
     * ON DELETE CASCADE and MySQL and PostgreSQL honour it, but SQLite enforces foreign keys only when
     * the connection asks it to, which this module's database wrapper does not do. Relying on the
     * cascade would therefore leave every entry behind on one of the three supported drivers.
     *
     * @throws \Exception
     */
    public function deleteUnopened(string $id): bool
    {
        $statusList = $this->findByIdOnPrimary($id);

        if (
            !$statusList instanceof StatusListRecord ||
            $statusList->isActive() ||
            $statusList->getDeactivatedAt() instanceof DateTimeImmutable
        ) {
            return false;
        }

        // Entries first, parent second. The other order looks more natural and is not retryable: a
        // crash in between would leave a list's worth of orphaned entries whose parent is already gone,
        // so a second call would find nothing to delete and return before cleaning them up. This way a
        // crash in between leaves an empty unopened list, which the next call simply finishes off.
        $this->database->write(
            sprintf(
                'DELETE FROM %s WHERE status_list_id = :status_list_id',
                $this->database->applyPrefix(StatusListEntryRepository::TABLE_NAME),
            ),
            ['status_list_id' => $id],
        );

        $affected = $this->database->write(
            sprintf(
                'DELETE FROM %s WHERE id = :id AND is_active = :is_active AND deactivated_at IS NULL',
                $this->getTableName(),
            ),
            [
                'id' => $id,
                'is_active' => [false, PDO::PARAM_BOOL],
            ],
        );

        return is_int($affected) && $affected > 0;
    }

    /**
     * Highest generation used in a pool so far, or 0 when the pool has no lists yet.
     */
    public function getHighestGeneration(string $poolId): int
    {
        $rows = $this->readPrimary(
            "SELECT MAX(generation) AS highest FROM {$this->getTableName()} WHERE pool_id = :pool_id",
            ['pool_id' => $poolId],
        );

        /** @var mixed $highest */
        $highest = $rows[0]['highest'] ?? null;

        return is_numeric($highest) ? (int)$highest : 0;
    }

    /**
     * Inserts a new list.
     *
     * The unique constraint on (pool_id, generation) is what settles a race between two workers both
     * deciding a successor is needed: one insert succeeds and the other fails. The caller does not need
     * to work out *why* it failed -- and could not reliably, since the database wrapper reports the
     * connection's error rather than the statement's -- because the recovery is the same for any
     * failure: read the pool again and use whichever list is active now.
     *
     * @param string $allowedStatuses Comma separated status values, already serialised by the caller.
     * Persisted rather than looked up from configuration later, so the list stays publishable exactly
     * as its holders resolved it even after the pool's settings change.
     * @throws \Exception
     */
    public function create(
        string $id,
        string $uri,
        string $poolId,
        string $policyFingerprint,
        int $generation,
        int $bits,
        int $capacity,
        string $allowedStatuses,
        int $ttlSeconds,
        int $tokenValiditySeconds,
        int $refreshIntervalSeconds,
        string $signingKeyId,
        StatusListKeyProfileEnum $keyProfile,
    ): void {
        $this->database->write(
            sprintf(
                'INSERT INTO %s (
                    id, uri, pool_id, policy_fingerprint, generation, bits, capacity, allowed_statuses,
                    ttl_seconds, token_validity_seconds, refresh_interval_seconds, signing_key_id,
                    key_profile, allocated_count, is_active, signed_token_content_hash, created_at
                ) VALUES (
                    :id, :uri, :pool_id, :policy_fingerprint, :generation, :bits, :capacity,
                    :allowed_statuses, :ttl_seconds, :token_validity_seconds, :refresh_interval_seconds,
                    :signing_key_id, :key_profile, :allocated_count, :is_active,
                    :signed_token_content_hash, :created_at
                )',
                $this->getTableName(),
            ),
            [
                'id' => $id,
                'uri' => $uri,
                'pool_id' => $poolId,
                'policy_fingerprint' => $policyFingerprint,
                'generation' => [$generation, PDO::PARAM_INT],
                'bits' => [$bits, PDO::PARAM_INT],
                'capacity' => [$capacity, PDO::PARAM_INT],
                'allowed_statuses' => $allowedStatuses,
                'ttl_seconds' => [$ttlSeconds, PDO::PARAM_INT],
                'token_validity_seconds' => [$tokenValiditySeconds, PDO::PARAM_INT],
                'refresh_interval_seconds' => [$refreshIntervalSeconds, PDO::PARAM_INT],
                'signing_key_id' => $signingKeyId,
                'key_profile' => $keyProfile->value,
                'allocated_count' => [0, PDO::PARAM_INT],
                // Created inactive, and activated only once every index has been seeded. Otherwise a
                // concurrent request could select this list and probe indices which do not exist yet,
                // find nothing to claim, and rotate away from a list which was perfectly good.
                'is_active' => [false, PDO::PARAM_BOOL],
                // Empty rather than null, so that the compare-and-set which publishes the first token
                // has something to match: a NULL would never equal a NULL and the update would affect
                // no rows.
                'signed_token_content_hash' => '',
                'created_at' => $this->nowForDatabase(),
            ],
        );
    }

    /**
     * Opens a freshly seeded list for allocation.
     *
     * Guarded on the list never having been deactivated, so that this can not resurrect a list which
     * was retired while it was being seeded.
     *
     * @throws \Exception
     */
    public function activate(string $id): bool
    {
        $affected = $this->database->write(
            sprintf(
                'UPDATE %s SET is_active = :new_is_active ' .
                'WHERE id = :id AND is_active = :current_is_active AND deactivated_at IS NULL',
                $this->getTableName(),
            ),
            [
                'new_is_active' => [true, PDO::PARAM_BOOL],
                'id' => $id,
                'current_is_active' => [false, PDO::PARAM_BOOL],
            ],
        );

        return is_int($affected) && $affected > 0;
    }

    /**
     * Stops a list accepting new allocations.
     *
     * @return bool Whether this call is the one which deactivated it, so that of several workers
     * deciding at the same time that the list is full, exactly one goes on to create the successor.
     * @throws \Exception
     */
    public function deactivate(string $id): bool
    {
        $affected = $this->database->write(
            sprintf(
                'UPDATE %s SET is_active = :new_is_active, deactivated_at = :deactivated_at ' .
                'WHERE id = :id AND is_active = :current_is_active',
                $this->getTableName(),
            ),
            [
                'new_is_active' => [false, PDO::PARAM_BOOL],
                'deactivated_at' => $this->nowForDatabase(),
                'id' => $id,
                'current_is_active' => [true, PDO::PARAM_BOOL],
            ],
        );

        return is_int($affected) && $affected > 0;
    }

    /**
     * Bumps the advisory allocation counter.
     *
     * Separate from the allocation itself, so it can undercount when a request dies in between. That is
     * tolerated because the counter only ever decides when to *consider* rotating, and running out of
     * probes rotates anyway.
     *
     * @throws \Exception
     */
    public function incrementAllocatedCount(string $id): void
    {
        $this->database->write(
            sprintf(
                'UPDATE %s SET allocated_count = allocated_count + 1 WHERE id = :id',
                $this->getTableName(),
            ),
            ['id' => $id],
        );
    }

    /**
     * Marks the published token as no longer representing the list's content.
     *
     * Called by whichever path changed a status, right after it changed it. Doing it in this order
     * matters: a crash between the two leaves a published token which is one refresh interval too
     * optimistic, whereas invalidating first and crashing before the change would lose the change
     * entirely. A spurious re-sign is cheap; a lost revocation is not.
     *
     * The guard keeps this a real modification when it matches, so that a driver reporting changed
     * rather than matched rows still reports it accurately.
     *
     * @throws \Exception
     */
    public function invalidatePublishedToken(string $id): void
    {
        $this->database->write(
            sprintf(
                "UPDATE %s SET signed_token_content_hash = '' " .
                "WHERE id = :id AND signed_token_content_hash <> ''",
                $this->getTableName(),
            ),
            ['id' => $id],
        );
    }

    /**
     * @param array<array-key,mixed> $rows
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function buildRecord(array $rows): ?StatusListRecord
    {
        /** @var mixed $row */
        $row = $rows === [] ? null : current($rows);

        return is_array($row) ? StatusListRecord::fromRow($row) : null;
    }

    /**
     * A read which is guaranteed not to come from a lagging secondary.
     *
     * @param array<string,mixed> $params
     * @return array<array-key,mixed>
     */
    protected function readPrimary(string $statement, array $params = []): array
    {
        return $this->database->readPrimary($statement, $params)->fetchAll();
    }

    /**
     * Timestamps are stored without a zone and read back as UTC, so a moment is converted to UTC on the
     * way in rather than having its wall clock written as-is. A value handed in as a local time would
     * otherwise be stored as that local wall clock and later read as though it were UTC, shifting it by
     * the offset.
     */
    protected function nowForDatabase(?DateTimeImmutable $moment = null): string
    {
        return ($moment ?? $this->helpers->dateTime()->getUtc())
            ->setTimezone(new DateTimeZone('UTC'))
            ->format(DateFormatsEnum::DB_DATETIME->value);
    }
}

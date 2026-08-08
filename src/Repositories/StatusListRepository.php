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
use SimpleSAML\Module\oidc\StatusList\Values\StatusListReconciliationCandidate;
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
     * Unconditional, and the counter is why. Clearing the hash says nothing when it is already clear,
     * so a signer which observed the empty hash before this call would still match it afterwards and
     * publish a token built before this change -- and since this writer has finished, nothing would
     * clear it again. Bumping a counter every time always changes the row, so that signer does not
     * match and rebuilds instead.
     *
     * @throws \Exception
     */
    public function invalidatePublishedToken(string $id): void
    {
        $this->database->write(
            sprintf(
                "UPDATE %s SET signed_token_content_hash = '', " .
                'invalidation_counter = invalidation_counter + 1 WHERE id = :id',
                $this->getTableName(),
            ),
            ['id' => $id],
        );
    }

    /**
     * Publishes a freshly signed token, provided the content it was signed over is still the content
     * which is published.
     *
     * The comparison against the hash the signer observed before it began is what makes this
     * single-flight: of several requests which all found the token stale and all signed one, the first
     * to arrive here matches and the rest do not, so the row never takes a token built from a snapshot
     * that a revocation has already superseded.
     *
     * The invalidation counter is compared alongside the hash and is what makes this sound while the
     * hash is empty. An empty hash is both "never published" and "invalidated", so on its own it cannot
     * distinguish a signer whose snapshot is still current from one which a revocation superseded after
     * it took its snapshot.
     *
     * @param string $observedContentHash The hash which was on the row when the signer decided to
     * re-sign, being '' when there was no published token at that point.
     * @param int $observedInvalidationCounter The counter read at the same moment.
     * @return bool Whether this token was the one published. False means another request published
     * first, or a status changed in between, and the caller must re-read rather than retry blindly.
     * @throws \Exception
     */
    public function publishToken(
        string $id,
        string $observedContentHash,
        int $observedInvalidationCounter,
        string $contentHash,
        string $signedToken,
        DateTimeImmutable $issuedAt,
        DateTimeImmutable $expiresAt,
    ): bool {
        $params = [
            'signed_token' => $signedToken,
            'content_hash' => $contentHash,
            'issued_at' => $this->nowForDatabase($issuedAt),
            'expires_at' => $this->nowForDatabase($expiresAt),
            'id' => $id,
            'observed_content_hash' => $observedContentHash,
            'observed_invalidation_counter' => [$observedInvalidationCounter, PDO::PARAM_INT],
        ];

        // Re-signing content which has not changed compares a value against itself, which settles
        // nothing: two nodes refreshing the same unchanged list would both match. Requiring the new
        // issuance time to be later restores a single winner.
        //
        // Only on this path, deliberately. Applied to every publication, a node whose clock runs behind
        // another's could not publish a content *change* until its clock caught up -- so a revocation
        // would sit unpublished for the length of the skew, which is exactly the outcome all of this
        // exists to prevent.
        $issuedAtGuard = '';

        if ($observedContentHash === $contentHash) {
            $issuedAtGuard = ' AND (signed_token_iat IS NULL OR signed_token_iat < :guard_issued_at)';
            // Under its own name because a repeated placeholder is not portable across drivers.
            $params['guard_issued_at'] = $this->nowForDatabase($issuedAt);
        }

        $affected = $this->database->write(
            sprintf(
                'UPDATE %s SET
                    signed_token = :signed_token,
                    signed_token_content_hash = :content_hash,
                    signed_token_iat = :issued_at,
                    signed_token_exp = :expires_at
                  WHERE id = :id
                    AND signed_token_content_hash = :observed_content_hash
                    AND invalidation_counter = :observed_invalidation_counter%s',
                $this->getTableName(),
                $issuedAtGuard,
            ),
            $params,
        );

        return is_int($affected) && $affected > 0;
    }

    /**
     * Lists which have a published token, in batches, for the reconciler to check.
     *
     * Paged by the last identifier seen rather than by an offset. The caller invalidates some of the
     * rows it is given, which removes them from this result set, so an offset would step over exactly
     * as many unexamined lists as were invalidated. A cursor is unaffected by rows leaving the set
     * behind it, and it does not re-count rows the database has already skipped past.
     *
     * Only the columns the reconciler uses are read. A row carries its published token, which for an
     * 8 bit list at the default capacity is a couple of hundred kilobytes, and reading whole rows would
     * move tens of megabytes per batch for a check which never looks at the token.
     *
     * @param ?string $afterId Resume after this list, or null to start from the beginning.
     * @return \SimpleSAML\Module\oidc\StatusList\Values\StatusListReconciliationCandidate[]
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function findPublished(int $limit, ?string $afterId = null): array
    {
        $params = [];
        $cursorCondition = '';

        if ($afterId !== null) {
            $cursorCondition = ' AND id > :after_id';
            $params['after_id'] = $afterId;
        }

        // Ordered by the primary key, which is arbitrary but stable -- all a cursor needs is that every
        // row is visited exactly once, not that they arrive in any meaningful order.
        //
        // The limit is interpolated rather than bound: MySQL rejects a bound LIMIT when PDO emulates
        // prepared statements, because the value arrives quoted as a string. It is an integer here, so
        // there is nothing to inject.
        $rows = $this->readPrimary(
            sprintf(
                'SELECT id, bits, capacity, signed_token_content_hash, invalidation_counter FROM %s ' .
                "WHERE signed_token_content_hash <> '' AND retired_at IS NULL%s ORDER BY id LIMIT %d",
                $this->getTableName(),
                $cursorCondition,
                max(0, $limit),
            ),
            $params,
        );

        $candidates = [];

        /** @var mixed $row */
        foreach ($rows as $row) {
            if (is_array($row)) {
                $candidates[] = StatusListReconciliationCandidate::fromRow($row);
            }
        }

        return $candidates;
    }

    /**
     * Invalidates a published token, but only while it is still the one which was examined.
     *
     * The reconciler decides a token is stale by comparing what it read a moment ago against the
     * entries as they are now. Between those two, a signer may have published a token which is
     * perfectly correct -- and clearing that would be pure churn, and could keep defeating an in-flight
     * signer indefinitely. Requiring both the hash and the counter to be unchanged means only the token
     * actually found wanting is cleared.
     *
     * This is why the unconditional invalidation exists separately: the path which changes a status
     * must always invalidate, since what it observed is by definition already superseded.
     *
     * @return bool Whether the token examined was still the published one, and was cleared.
     * @throws \Exception
     */
    public function invalidatePublishedTokenIfUnchanged(
        string $id,
        string $observedContentHash,
        int $observedInvalidationCounter,
    ): bool {
        $affected = $this->database->write(
            sprintf(
                "UPDATE %s SET signed_token_content_hash = '', " .
                'invalidation_counter = invalidation_counter + 1 ' .
                'WHERE id = :id
                   AND signed_token_content_hash = :observed_content_hash
                   AND invalidation_counter = :observed_invalidation_counter',
                $this->getTableName(),
            ),
            [
                'id' => $id,
                'observed_content_hash' => $observedContentHash,
                'observed_invalidation_counter' => [$observedInvalidationCounter, PDO::PARAM_INT],
            ],
        );

        return is_int($affected) && $affected > 0;
    }

    /**
     * Stops lists accepting allocations which they were never going to receive again anyway.
     *
     * A list is only selected for allocation while its pool and its policy fingerprint both match the
     * current configuration, so changing a pool's settings or rotating the signing key leaves the lists
     * created under the previous policy active but unreachable. Nothing would ever fill them, so nothing
     * would ever deactivate them, and retirement begins with deactivation -- they would go on being
     * served for ever while holding credentials which all expired years ago.
     *
     * This changes nothing an issuer or a wallet can observe. The lists were already never going to be
     * allocated into; all this does is start the clock which lets them eventually be retired.
     *
     * @param array<string,string> $currentPolicyByPoolId Pool identifier to the policy fingerprint
     * lists of that pool are currently created under. An empty map means no pool is configured to
     * allocate at all, in which case every active list is superseded.
     * @return int How many lists were deactivated.
     * @throws \Exception
     */
    public function deactivateSuperseded(array $currentPolicyByPoolId): int
    {
        $params = [
            'deactivated_at' => $this->nowForDatabase(),
            'new_is_active' => [false, PDO::PARAM_BOOL],
            'current_is_active' => [true, PDO::PARAM_BOOL],
        ];

        $currentPolicies = [];
        $position = 0;

        foreach ($currentPolicyByPoolId as $poolId => $policyFingerprint) {
            // Each value under its own placeholder name, since a repeated one is not portable across
            // drivers.
            $currentPolicies[] = sprintf(
                '(pool_id = :pool_%d AND policy_fingerprint = :policy_%d)',
                $position,
                $position,
            );
            $params['pool_' . $position] = $poolId;
            $params['policy_' . $position] = $policyFingerprint;
            $position++;
        }

        $supersededCondition = $currentPolicies === [] ?
        '' :
        sprintf(' AND NOT (%s)', implode(' OR ', $currentPolicies));

        $affected = $this->database->write(
            sprintf(
                'UPDATE %s SET is_active = :new_is_active, deactivated_at = :deactivated_at ' .
                'WHERE is_active = :current_is_active AND retired_at IS NULL%s',
                $this->getTableName(),
                $supersededCondition,
            ),
            $params,
        );

        return is_int($affected) ? $affected : 0;
    }

    /**
     * Lists which stopped accepting allocations long enough ago to be worth examining for retirement.
     *
     * Deactivation is only the first of the two waits. Whether a list has served out the second one
     * depends on when the credentials inside it expire, which this does not work out -- that is an
     * aggregate per list, and one worth avoiding for the lists which have not even served out the first.
     *
     * It does exclude the lists which can never serve it out, which is a different thing. A list holding
     * a credential without an expiry is not waiting for anything; it is permanently ineligible, and
     * leaving it in would let a deployment with enough of them fill every batch a run is willing to work
     * through and starve the eligible lists behind them. Since every run starts from the beginning, that
     * would not correct itself.
     *
     * The `deactivated_at IS NOT NULL` test is what keeps this away from lists which are inactive for the
     * other reason: a list is created inactive and stays that way while its entries are being seeded, and
     * one abandoned midway through that is dealt with by deleting it, not by retiring it.
     *
     * Paged by the last identifier seen rather than by an offset, because the caller retires some of the
     * rows it is given and that takes them out of this result set.
     *
     * @param \DateTimeImmutable $deactivatedBefore Ignore anything deactivated more recently than this.
     * @param ?string $afterId Resume after this list, or null to start from the beginning.
     * @return string[] Identifiers, in the arbitrary but stable order of the primary key.
     */
    public function findRetirementCandidates(
        DateTimeImmutable $deactivatedBefore,
        int $limit,
        ?string $afterId = null,
    ): array {
        $params = [
            'is_active' => [false, PDO::PARAM_BOOL],
            'deactivated_before' => $this->nowForDatabase($deactivatedBefore),
            'allocated' => [true, PDO::PARAM_BOOL],
        ];
        $cursorCondition = '';

        if ($afterId !== null) {
            $cursorCondition = ' AND id > :after_id';
            $params['after_id'] = $afterId;
        }

        // Only the identifier is read. A row carries its published token, which for a list at the
        // default capacity is a couple of hundred kilobytes, and none of that is looked at here.
        //
        // The limit is interpolated rather than bound: MySQL rejects a bound LIMIT when PDO emulates
        // prepared statements, because the value arrives quoted as a string. It is an integer here, so
        // there is nothing to inject.
        return $this->readIdentifiers(
            sprintf(
                'SELECT id FROM %1$s WHERE is_active = :is_active AND retired_at IS NULL ' .
                'AND deactivated_at IS NOT NULL AND deactivated_at <= :deactivated_before ' .
                'AND NOT EXISTS (SELECT 1 FROM %2$s WHERE status_list_id = %1$s.id ' .
                'AND allocated = :allocated AND expires_at IS NULL)%3$s ' .
                'ORDER BY id LIMIT %4$d',
                $this->getTableName(),
                $this->database->applyPrefix(StatusListEntryRepository::TABLE_NAME),
                $cursorCondition,
                max(0, $limit),
            ),
            $params,
        );
    }

    /**
     * Stops a list being served, and gives back the token it was being served from.
     *
     * The last step of the lifecycle, and the only irreversible one: the list's URI is written into every
     * credential which was issued from it, and from here on fetching it answers 404. That is why nothing
     * arrives here until every one of those credentials has expired and a further grace period has
     * passed on top.
     *
     * That condition is tested here rather than by the caller, and this is the point of the method. A
     * caller which reads the entries, decides they have all expired, and then retires the list in a
     * second statement has a gap between the two, and an issuance which was already in flight can land
     * in it -- leaving a credential which is perfectly valid naming a list which now answers 404. There
     * are no transactions to close that gap with, so the test and the retirement are the same statement,
     * and a list which stopped qualifying in the meantime simply matches no rows.
     *
     * The published token is dropped in the same statement too, since a retired list is never served
     * from it again. Its content hash goes back to the empty string and the invalidation counter moves,
     * which together keep a signer that is mid-flight from publishing a token onto a list which has just
     * been retired out from under it.
     *
     * @param \DateTimeImmutable $spentBefore Every credential in the list must have expired before this
     * moment. A credential with no expiry at all never qualifies, however far ahead this is.
     * @return bool Whether this call is the one which retired it. False means another worker got there
     * first, or the list turned out to still be holding something.
     * @throws \Exception
     */
    public function retire(string $id, DateTimeImmutable $spentBefore): bool
    {
        $affected = $this->database->write(
            sprintf(
                "UPDATE %1\$s SET
                    retired_at = :retired_at,
                    signed_token = NULL,
                    signed_token_content_hash = '',
                    signed_token_iat = NULL,
                    signed_token_exp = NULL,
                    invalidation_counter = invalidation_counter + 1
                  WHERE id = :id AND is_active = :is_active AND retired_at IS NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM %2\$s WHERE status_list_id = :guarded_id
                          AND allocated = :allocated
                          AND (expires_at IS NULL OR expires_at >= :spent_before)
                    )",
                $this->getTableName(),
                $this->database->applyPrefix(StatusListEntryRepository::TABLE_NAME),
            ),
            [
                'retired_at' => $this->nowForDatabase(),
                'id' => $id,
                'is_active' => [false, PDO::PARAM_BOOL],
                // The same value as :id, under its own name because a repeated placeholder is not
                // portable across drivers.
                'guarded_id' => $id,
                'allocated' => [true, PDO::PARAM_BOOL],
                'spent_before' => $this->nowForDatabase($spentBefore),
            ],
        );

        return is_int($affected) && $affected > 0;
    }

    /**
     * Retired lists which still have entries behind them, and have been retired long enough for that to
     * be safe to act on.
     *
     * Removing those entries is bounded per run, so a list of default capacity takes several runs to
     * clear and has to be found again by each of them. The existence test is what distinguishes a list
     * still being worked through from the ones already dealt with, which accumulate for as long as the
     * deployment runs and would otherwise be re-examined for ever.
     *
     * The wait since retirement is the point of the cut-off, and it is not the same wait as the one
     * before retirement. Retiring a list can not be serialised against an issuance which was already in
     * flight -- the two statements write different rows, so neither conflicts with the other -- so a
     * credential can in principle be written into a list moments after it was retired. Retirement alone
     * only makes that credential unverifiable; removing the entries as well destroys the record that it
     * exists at all. Leaving the rows a while longer keeps them there to be found.
     *
     * @param \DateTimeImmutable $retiredBefore Ignore lists retired more recently than this.
     * @return string[]
     */
    public function findRetiredWithEntries(int $limit, DateTimeImmutable $retiredBefore): array
    {
        return $this->readIdentifiers(
            sprintf(
                'SELECT id FROM %1$s WHERE retired_at IS NOT NULL AND retired_at <= :retired_before ' .
                'AND EXISTS (SELECT 1 FROM %2$s WHERE status_list_id = %1$s.id) ORDER BY id LIMIT %3$d',
                $this->getTableName(),
                $this->database->applyPrefix(StatusListEntryRepository::TABLE_NAME),
                max(0, $limit),
            ),
            ['retired_before' => $this->nowForDatabase($retiredBefore)],
        );
    }

    /**
     * @param array<string,mixed> $params
     * @return string[]
     */
    protected function readIdentifiers(string $statement, array $params = []): array
    {
        $identifiers = [];

        /** @var mixed $row */
        foreach ($this->readPrimary($statement, $params) as $row) {
            /** @var mixed $id */
            $id = is_array($row) ? ($row['id'] ?? null) : null;

            if (is_scalar($id)) {
                $identifiers[] = (string)$id;
            }
        }

        return $identifiers;
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

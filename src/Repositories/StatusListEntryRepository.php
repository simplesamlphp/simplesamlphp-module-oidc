<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

/**
 * Storage for the individual indices of a Status List.
 *
 * Two things about this table are unusual and deliberate.
 *
 * Every index exists as a row from the moment the list is created, rather than being inserted when it
 * is handed out. Claiming an index is then an UPDATE which only matches while the index is still free,
 * and the number of rows it affected says whether this caller got it. That removes the need to detect a
 * unique constraint violation, which this module can not do reliably: the database wrapper records the
 * connection's error rather than the failing statement's, and rethrows without the original, so on some
 * drivers a constraint violation is indistinguishable from any other failure.
 *
 * Rows are never removed while the list is served, because an index which was handed out once must
 * never be handed out again, even long after the credential holding it has expired.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Repositories\StatusListEntryRepositoryTest
 */
class StatusListEntryRepository extends AbstractDatabaseRepository
{
    final public const string TABLE_NAME = 'oidc_status_list_entry';

    /**
     * Rows inserted per statement while seeding a list.
     *
     * Two placeholders per row, so this stays an order of magnitude under the 65535 a MySQL prepared
     * statement allows, while keeping the number of round trips for a default sized list in the
     * hundreds rather than the hundred thousands.
     */
    protected const int SEED_BATCH_SIZE = 500;

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
     * The form a credential identifier is looked up by.
     *
     * The identifier itself is a URI, which has no length this schema could safely assume, so the
     * column carrying it is unindexed text and a fixed width hash of it carries the unique index. This
     * lives here because it is a property of how the row is stored, and every caller which stores or
     * finds one has to agree on it.
     */
    public function hashCredentialId(string $credentialId): string
    {
        return hash('sha256', $credentialId);
    }

    /**
     * Creates every index of a newly created list, unallocated and Valid.
     *
     * Only the two key columns are written; `allocated` and `status` take their column defaults, which
     * halves the statement size and keeps the defaults defined in exactly one place.
     *
     * @throws \Exception
     */
    public function seed(string $statusListId, int $capacity): void
    {
        for ($offset = 0; $offset < $capacity; $offset += self::SEED_BATCH_SIZE) {
            $batchSize = min(self::SEED_BATCH_SIZE, $capacity - $offset);
            $placeholders = [];
            $params = [];

            for ($position = 0; $position < $batchSize; $position++) {
                // Each value gets its own placeholder name. Repeating one is not portable: PDO turns
                // named placeholders into positional ones for some drivers, and a repeat then binds
                // only the first occurrence.
                $placeholders[] = sprintf('(:list_%d, :idx_%d)', $position, $position);
                $params['list_' . $position] = $statusListId;
                $params['idx_' . $position] = [$offset + $position, PDO::PARAM_INT];
            }

            $this->database->write(
                sprintf(
                    'INSERT INTO %s (status_list_id, idx) VALUES %s',
                    $this->getTableName(),
                    implode(', ', $placeholders),
                ),
                $params,
            );
        }
    }

    /**
     * Claims one index for a credential, if it is still free and its list still accepts allocations.
     *
     * The linkage is written by the same statement which claims the index, so there is never a moment
     * where an index is taken but nothing records what took it.
     *
     * @return bool Whether this caller got the index. False means another request claimed it first, or
     * the list stopped accepting allocations, and the caller should probe again or select another list.
     * @throws \Exception
     */
    public function allocate(
        string $statusListId,
        int $idx,
        string $credentialId,
        string $credentialIdHash,
        string $credentialConfigurationId,
        ?string $subjectRef,
        ?DateTimeImmutable $expiresAt,
        ?DateTimeImmutable $issuedAt = null,
    ): bool {
        $now = $this->formatForDatabase($issuedAt ?? $this->helpers->dateTime()->getUtc());
        $statusListTableName = $this->database->applyPrefix(StatusListRepository::TABLE_NAME);

        $affected = $this->database->write(
            sprintf(
                'UPDATE %s SET
                    allocated = :allocated,
                    credential_id = :credential_id,
                    credential_id_hash = :credential_id_hash,
                    credential_configuration_id = :credential_configuration_id,
                    subject_ref = :subject_ref,
                    issued_at = :issued_at,
                    expires_at = :expires_at,
                    updated_at = :updated_at
                 WHERE status_list_id = :status_list_id
                   AND idx = :idx
                   AND allocated = :is_free
                   AND EXISTS (
                        SELECT 1 FROM %s WHERE id = :guarded_status_list_id AND is_active = :is_active
                   )',
                $this->getTableName(),
                $statusListTableName,
            ),
            [
                'allocated' => [true, PDO::PARAM_BOOL],
                'credential_id' => $credentialId,
                'credential_id_hash' => $credentialIdHash,
                'credential_configuration_id' => $credentialConfigurationId,
                'subject_ref' => $subjectRef,
                'issued_at' => $now,
                'expires_at' => $expiresAt instanceof DateTimeImmutable ?
                    $this->formatForDatabase($expiresAt) :
                    null,
                'updated_at' => $now,
                'status_list_id' => $statusListId,
                'idx' => [$idx, PDO::PARAM_INT],
                'is_free' => [false, PDO::PARAM_BOOL],
                // The same value as :status_list_id, under its own name because a repeated placeholder
                // is not portable across drivers.
                'guarded_status_list_id' => $statusListId,
                'is_active' => [true, PDO::PARAM_BOOL],
            ],
        );

        return is_int($affected) && $affected > 0;
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function findByCredentialIdHash(string $credentialIdHash): ?StatusListEntryRecord
    {
        return $this->buildRecord(
            $this->readPrimary(
                "SELECT * FROM {$this->getTableName()} WHERE credential_id_hash = :credential_id_hash",
                ['credential_id_hash' => $credentialIdHash],
            ),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function findByListAndIdx(string $statusListId, int $idx): ?StatusListEntryRecord
    {
        return $this->buildRecord(
            $this->readPrimary(
                "SELECT * FROM {$this->getTableName()} WHERE status_list_id = :status_list_id AND idx = :idx",
                [
                    'status_list_id' => $statusListId,
                    'idx' => [$idx, PDO::PARAM_INT],
                ],
            ),
        );
    }

    /**
     * Moves an allocated entry from one status to another.
     *
     * Conditioned on the status the caller observed, so that two concurrent changes do not silently
     * overwrite one another: the second one finds the status is no longer what it read and gets false
     * back rather than clobbering the first.
     *
     * @return bool Whether the change was applied.
     * @throws \Exception
     */
    public function updateStatus(
        string $statusListId,
        int $idx,
        int $observedStatus,
        int $newStatus,
    ): bool {
        $affected = $this->database->write(
            sprintf(
                'UPDATE %s SET status = :new_status, updated_at = :updated_at
                  WHERE status_list_id = :status_list_id
                    AND idx = :idx
                    AND allocated = :allocated
                    AND status = :observed_status',
                $this->getTableName(),
            ),
            [
                'new_status' => [$newStatus, PDO::PARAM_INT],
                'updated_at' => $this->formatForDatabase($this->helpers->dateTime()->getUtc()),
                'status_list_id' => $statusListId,
                'idx' => [$idx, PDO::PARAM_INT],
                'allocated' => [true, PDO::PARAM_BOOL],
                'observed_status' => [$observedStatus, PDO::PARAM_INT],
            ],
        );

        return is_int($affected) && $affected > 0;
    }

    /**
     * Index to status for every entry which is not Valid, which is all a Status List needs in order to
     * be rebuilt: every index the query does not return is Valid, including the ones never allocated.
     *
     * A primary read, since this is what gets signed and published.
     *
     * @return array<int,int>
     */
    public function findNonValidStatuses(string $statusListId): array
    {
        $rows = $this->readPrimary(
            "SELECT idx, status FROM {$this->getTableName()} " .
            'WHERE status_list_id = :status_list_id AND status <> :valid_status ORDER BY idx',
            [
                'status_list_id' => $statusListId,
                'valid_status' => [0, PDO::PARAM_INT],
            ],
        );

        $statuses = [];

        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            /** @var mixed $idx */
            $idx = $row['idx'] ?? null;
            /** @var mixed $status */
            $status = $row['status'] ?? null;

            if (!is_numeric($idx) || !is_numeric($status)) {
                continue;
            }

            $statuses[(int)$idx] = (int)$status;
        }

        return $statuses;
    }

    public function countAllocated(string $statusListId): int
    {
        $rows = $this->readPrimary(
            "SELECT COUNT(*) AS allocated_total FROM {$this->getTableName()} " .
            'WHERE status_list_id = :status_list_id AND allocated = :allocated',
            [
                'status_list_id' => $statusListId,
                'allocated' => [true, PDO::PARAM_BOOL],
            ],
        );

        /** @var mixed $total */
        $total = $rows[0]['allocated_total'] ?? null;

        return is_numeric($total) ? (int)$total : 0;
    }

    /**
     * @param array<array-key,mixed> $rows
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function buildRecord(array $rows): ?StatusListEntryRecord
    {
        /** @var mixed $row */
        $row = $rows === [] ? null : current($rows);

        return is_array($row) ? StatusListEntryRecord::fromRow($row) : null;
    }

    /**
     * @param array<string,mixed> $params
     * @return array<array-key,mixed>
     */
    protected function readPrimary(string $statement, array $params = []): array
    {
        return $this->database->readPrimary($statement, $params)->fetchAll();
    }

    /**
     * Timestamps are stored without a zone and read back as UTC, so a moment is converted to UTC on the
     * way in rather than having its wall clock written as-is. Without this, an expiry handed in as a
     * local time would be stored as that local wall clock and later read as though it were UTC, moving
     * the credential's expiry by the offset -- which for a deployment west of UTC means expiring it
     * early, and can retire a list while a credential in it is still live.
     */
    protected function formatForDatabase(DateTimeImmutable $moment): string
    {
        return $moment->setTimezone(new DateTimeZone('UTC'))->format(DateFormatsEnum::DB_DATETIME->value);
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use DateTimeImmutable;
use DateTimeZone;
use PDO;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusChangeSourceEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

/**
 * Trail of Status List status changes.
 *
 * Written before the change it describes, not after. Without transactions the two can not be made
 * atomic, so the ordering picks which way they can disagree: an audit row for a change which did not
 * take effect is visible and reconcilable, whereas a change with no audit row is a silent one.
 *
 * **A row here is a request, not a receipt.** There is no outcome column, and there deliberately is
 * not one: writing the outcome would be a third write which can fail in its own right, leaving rows
 * stuck in a "pending" state that says even less than no column at all. So a row records that an actor
 * asked for a transition at a moment, and nothing more. Whether it took effect is answered by the entry
 * itself, which is the only authority on what a credential's status is. Two actors asking for the same
 * transition at once therefore leave two rows, both true, though only one of them changed anything.
 *
 * The old status recorded is the one the caller observed, not an authoritative before-image. Two
 * concurrent changes can interleave between the observation and the update, so this is a record of what
 * each actor believed and asked for, which is what an audit trail is for.
 *
 * Only the hash of a credential ID is stored, never the ID itself, so that the trail does not outlive
 * the linkage which is deliberately deleted once a credential expires.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Repositories\StatusAuditRepositoryTest
 */
class StatusAuditRepository extends AbstractDatabaseRepository
{
    final public const string TABLE_NAME = 'oidc_status_audit';

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
     * @param ?string $actorRef Who asked for the change: an API token principal's name, an
     * administrator's identifier, or null for an unattended one. Never the API token itself, which
     * would put a bearer secret in the audit trail.
     * @return string The identifier of the row written, so that a caller whose change then fails can
     * name the row it left behind rather than leaving someone to find it by timestamp.
     * @throws \Exception
     */
    public function record(
        string $credentialIdHash,
        string $statusListId,
        int $idx,
        int $observedOldStatus,
        int $newStatus,
        StatusChangeSourceEnum $source,
        ?string $actorRef = null,
        ?DateTimeImmutable $createdAt = null,
    ): string {
        $id = $this->helpers->random()->getIdentifier();

        $this->database->write(
            sprintf(
                'INSERT INTO %s (
                    id, credential_id_hash, status_list_id, idx, old_status, new_status, actor_ref,
                    source, created_at
                 ) VALUES (
                    :id, :credential_id_hash, :status_list_id, :idx, :old_status, :new_status,
                    :actor_ref, :source, :created_at
                 )',
                $this->getTableName(),
            ),
            [
                'id' => $id,
                'credential_id_hash' => $credentialIdHash,
                'status_list_id' => $statusListId,
                'idx' => [$idx, PDO::PARAM_INT],
                'old_status' => [$observedOldStatus, PDO::PARAM_INT],
                'new_status' => [$newStatus, PDO::PARAM_INT],
                'actor_ref' => $actorRef,
                'source' => $source->value,
                // Normalised rather than formatted as given. The column carries no timezone, so a
                // moment written in the server's local time is indistinguishable from one written in
                // UTC, and the two would be ordered and pruned against each other as though they were
                // the same scale. Every other Status List table stores UTC; so does this one.
                'created_at' => ($createdAt ?? $this->helpers->dateTime()->getUtc())
                    ->setTimezone(new DateTimeZone('UTC'))
                    ->format(DateFormatsEnum::DB_DATETIME->value),
            ],
        );

        return $id;
    }
}

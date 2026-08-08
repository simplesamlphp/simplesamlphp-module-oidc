<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use SimpleSAML\Module\oidc\Exceptions\StatusConflictException;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Contracts\StatusUpdaterInterface;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

/**
 * Changes the status of an allocated Status List index.
 *
 * The order of the two writes this performs is deliberate and is the part worth understanding. First
 * the entry is updated, then the list's published token is marked stale. There are no transactions
 * here, so the two can not be made atomic, and the ordering decides which way they can disagree:
 * crashing in between leaves a published token which is at most one refresh interval too optimistic,
 * whereas invalidating first and crashing before the update would lose the change outright. A needless
 * re-sign costs nothing; a lost revocation is a revoked credential still reading as valid.
 *
 * What this does not do is republish. That happens when the list is next fetched, so that revoking a
 * credential does not put compression and signing of a list which may be hundreds of kilobytes on the
 * revocation request's critical path.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\DbStatusUpdaterTest
 */
class DbStatusUpdater implements StatusUpdaterInterface
{
    /**
     * Times the read-compare-set is retried when something else changes the entry in between. Status
     * changes for one credential are rare enough that losing three times running means contention this
     * is not going to win by trying harder.
     */
    protected const int MAX_UPDATE_ATTEMPTS = 3;

    public function __construct(
        protected readonly StatusListRepository $statusListRepository,
        protected readonly StatusListEntryRepository $statusListEntryRepository,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException
     * @throws \Exception
     */
    public function setStatus(string $statusListId, int $idx, StatusTypeEnum $status): bool
    {
        $statusList = $this->requireList($statusListId);

        $this->enforceStatusFits($statusList, $status);

        // Read, compare and set, and try again against the value which actually got there. Returning
        // false for a lost race would be indistinguishable from the entry already holding the requested
        // status, and those mean opposite things: one says the credential is in the state that was
        // asked for, the other says it is in somebody else's.
        for ($attempt = 1; $attempt <= self::MAX_UPDATE_ATTEMPTS; $attempt++) {
            $entry = $this->requireAllocatedEntry($statusListId, $idx);

            if ($entry->getStatus() === $status->value) {
                $this->loggerService->debug(
                    'Status List entry already holds the requested status, leaving it alone.',
                    ['statusListId' => $statusListId, 'idx' => $idx, 'status' => $status->value],
                );

                return false;
            }

            $isUpdated = $this->statusListEntryRepository->updateStatus(
                $statusListId,
                $idx,
                $entry->getStatus(),
                $status->value,
            );

            if (!$isUpdated) {
                $this->loggerService->warning(
                    'Status List entry changed while it was being updated, retrying.',
                    [
                        'statusListId' => $statusListId,
                        'idx' => $idx,
                        'observedStatus' => $entry->getStatus(),
                        'requestedStatus' => $status->value,
                        'attempt' => $attempt,
                    ],
                );

                continue;
            }

            // Only now, and always after the entry write. See the note on this class.
            $this->statusListRepository->invalidatePublishedToken($statusListId);

            $this->loggerService->info(
                'Changed a Status List entry status.',
                [
                    'statusListId' => $statusListId,
                    'idx' => $idx,
                    'oldStatus' => $entry->getStatus(),
                    'newStatus' => $status->value,
                ],
            );

            return true;
        }

        throw new StatusConflictException(
            sprintf(
                'Status List "%s" index %d kept being changed by something else, so it could not be set ' .
                'to %s (0x%02X) after %d attempts. It holds whatever those changes left, not the ' .
                'requested status.',
                $statusListId,
                $idx,
                $status->name,
                $status->value,
                self::MAX_UPDATE_ATTEMPTS,
            ),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \Exception
     */
    public function enforceCanRepresent(string $statusListId, StatusTypeEnum $status): void
    {
        $this->enforceStatusFits($this->requireList($statusListId), $status);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \Exception
     */
    protected function requireList(string $statusListId): StatusListRecord
    {
        $statusList = $this->statusListRepository->findByIdOnPrimary($statusListId);

        if (!$statusList instanceof StatusListRecord) {
            throw new StatusListException(sprintf('Status List "%s" was not found.', $statusListId));
        }

        return $statusList;
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function getStatusValue(string $statusListId, int $idx): ?int
    {
        $entry = $this->statusListEntryRepository->findByListAndIdx($statusListId, $idx);

        if (!$entry instanceof StatusListEntryRecord || !$entry->isAllocated()) {
            return null;
        }

        return $entry->getStatus();
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function requireAllocatedEntry(string $statusListId, int $idx): StatusListEntryRecord
    {
        $entry = $this->statusListEntryRepository->findByListAndIdx($statusListId, $idx);

        if (!$entry instanceof StatusListEntryRecord) {
            throw new StatusListException(
                sprintf('Status List "%s" has no entry at index %d.', $statusListId, $idx),
            );
        }

        // Every index exists as a row from the moment the list is created, so an unallocated row is not
        // an entry which was issued to anything, and changing its status would be describing a
        // credential which does not exist.
        if (!$entry->isAllocated()) {
            throw new StatusListException(
                sprintf(
                    'Status List "%s" index %d was never allocated, so its status can not be changed.',
                    $statusListId,
                    $idx,
                ),
            );
        }

        return $entry;
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException
     */
    protected function enforceStatusFits(StatusListRecord $statusList, StatusTypeEnum $status): void
    {
        // Checked against what the list itself records, not against the pool's current configuration.
        // Raising a pool's bits does not change lists which already exist, so the list is the only
        // thing which can answer what it is able to carry.
        $largestRepresentable = (1 << $statusList->getBits()) - 1;

        if ($status->value > $largestRepresentable) {
            throw new UnsupportedStatusException(
                sprintf(
                    'Status List "%s" carries %d bit(s) per entry, so it can not represent the status ' .
                    '%s (0x%02X). That is fixed for the lifetime of this list; a pool needing this ' .
                    'status must be configured with at least %d bits before its lists are created.',
                    $statusList->getId(),
                    $statusList->getBits(),
                    $status->name,
                    $status->value,
                    $status->requiredBits(),
                ),
            );
        }

        if (!$statusList->isStatusValueAllowed($status->value)) {
            throw new UnsupportedStatusException(
                sprintf(
                    'Status List "%s" was created allowing only the statuses %s, so it can not be set ' .
                    'to %s (0x%02X).',
                    $statusList->getId(),
                    $statusList->getAllowedStatusesAsString(),
                    $status->name,
                    $status->value,
                ),
            );
        }
    }
}

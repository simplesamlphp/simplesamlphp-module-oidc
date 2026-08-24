<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\Codebooks\StatusChangeSourceEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\StatusAuditRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Contracts\StatusUpdaterInterface;
use SimpleSAML\Module\oidc\StatusList\Values\CredentialStatusChange;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;
use Throwable;

/**
 * Changes the status of an issued credential, addressed the way the outside world knows it.
 *
 * Everything below this point works in list IDs and indices, which is what the storage is keyed on and
 * what the published token is built from. Nothing outside knows those: an administrator, or a system
 * asking for a credential to be withdrawn, has the credential's own identifier and nothing else. This
 * turns one into the other, records the attempt, and applies it.
 *
 * Any surface which withdraws a credential should come through here rather than reaching for the
 * updater directly, so that no status change escapes the audit trail.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\CredentialStatusServiceTest
 */
class CredentialStatusService
{
    public function __construct(
        protected readonly StatusListEntryRepository $statusListEntryRepository,
        protected readonly StatusUpdaterInterface $statusUpdater,
        protected readonly StatusAuditRepository $statusAuditRepository,
        protected readonly Helpers $helpers,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * @param string $credentialId The identifier the credential carries as its `jti`.
     * @param ?string $actorRef Who asked, as a name rather than a secret. Null for an unattended
     * change, which is what a scheduled task is.
     * @return ?\SimpleSAML\Module\oidc\StatusList\Values\CredentialStatusChange Null when no credential of that
     *   identifier can be acted on, which covers one that was never issued here and one which has expired alike.
     * @throws \SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException When the list this
     * credential sits in can not represent the requested status. Permanent, not worth retrying.
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusConflictException When concurrent changes kept
     * winning, so the credential holds something other than what was asked for.
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \Exception
     */
    public function setStatus(
        string $credentialId,
        StatusTypeEnum $status,
        StatusChangeSourceEnum $source,
        ?string $actorRef = null,
    ): ?CredentialStatusChange {
        $credentialIdHash = $this->statusListEntryRepository->hashCredentialId($credentialId);
        $entry = $this->statusListEntryRepository->findByCredentialIdHash($credentialIdHash);

        if (!$this->isActionable($entry)) {
            $this->loggerService->info(
                'A status change was requested for a credential which can not be acted on.',
                ['credentialIdHash' => $credentialIdHash, 'source' => $source->value, 'actorRef' => $actorRef],
            );

            return null;
        }

        /** @var \SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord $entry */
        $observedStatus = $entry->getStatus();

        // Already there. Repeating a request is how a caller which never saw an answer recovers, so it
        // is a success rather than an error, and it writes nothing: the change it is repeating was
        // recorded when it first happened, and recording it again would fill the trail with rows for
        // things that did not occur.
        if ($observedStatus === $status->value) {
            return new CredentialStatusChange(
                $entry->getStatusListId(),
                $entry->getIdx(),
                $observedStatus,
                $status,
                false,
            );
        }

        // Asked before anything is written, because this is the one failure which is not a failure at
        // all: whether a list can carry a status is fixed when the list is created and can never
        // become true later. Recording it and then refusing it would leave a permanent row describing
        // a transition that was never possible.
        $this->statusUpdater->enforceCanRepresent($entry->getStatusListId(), $status);

        // Audit first. These are separate tables and there are no transactions here, so the two writes
        // can not be made atomic and the ordering decides which way they are allowed to disagree.
        // Recording first means a crash in between leaves a row describing a change which did not take
        // effect, which reconciliation against the entry can find. The other order loses the record of
        // a change which did, and nothing would ever reveal it. This is not atomicity and is not
        // claimed to be.
        $auditId = $this->statusAuditRepository->record(
            $credentialIdHash,
            $entry->getStatusListId(),
            $entry->getIdx(),
            $observedStatus,
            $status->value,
            $source,
            $actorRef,
        );

        try {
            $isChanged = $this->statusUpdater->setStatus($entry->getStatusListId(), $entry->getIdx(), $status);
        } catch (Throwable $throwable) {
            $this->loggerService->error(
                'A recorded status change could not be applied, so the audit trail holds a transition ' .
                'which did not take effect. The row is named here so it can be found.',
                [
                    'auditId' => $auditId,
                    'credentialIdHash' => $credentialIdHash,
                    'statusListId' => $entry->getStatusListId(),
                    'idx' => $entry->getIdx(),
                    'observedStatus' => $observedStatus,
                    'requestedStatus' => $status->value,
                    'error' => $throwable->getMessage(),
                ],
            );

            throw $throwable;
        }

        $this->loggerService->info(
            'Changed the status of a credential.',
            [
                'credentialIdHash' => $credentialIdHash,
                'statusListId' => $entry->getStatusListId(),
                'idx' => $entry->getIdx(),
                'observedStatus' => $observedStatus,
                'newStatus' => $status->value,
                'source' => $source->value,
                'actorRef' => $actorRef,
            ],
        );

        return new CredentialStatusChange(
            $entry->getStatusListId(),
            $entry->getIdx(),
            $observedStatus,
            $status,
            $isChanged,
        );
    }


    /**
     * The status a credential currently holds, or null when there is none to report.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \Exception
     */
    public function getStatusValue(string $credentialId): ?int
    {
        $entry = $this->statusListEntryRepository->findByCredentialIdHash(
            $this->statusListEntryRepository->hashCredentialId($credentialId),
        );

        return $this->isActionable($entry) ? $entry?->getStatus() : null;
    }


    /**
     * Whether a status change against this entry would mean anything.
     *
     * Three cases are answered the same way on purpose. A credential which was never issued here has
     * no entry. One issued by a configuration which does not use Status Lists has no entry either. And
     * an expired one is already refused by every Relying Party on its own claims, so withdrawing it
     * changes nothing that is not already true -- besides which, the linkage that finds it is deleted
     * once it expires, so this would become a lookup miss anyway. Distinguishing them in the answer
     * would tell a caller which identifiers exist here, which is not theirs to learn.
     *
     * @throws \Exception
     */
    protected function isActionable(?StatusListEntryRecord $entry): bool
    {
        if (!$entry instanceof StatusListEntryRecord || !$entry->isAllocated()) {
            return false;
        }

        $expiresAt = $entry->getExpiresAt();

        if (!$expiresAt instanceof DateTimeImmutable) {
            return true;
        }

        return $expiresAt > $this->helpers->dateTime()->getUtc();
    }
}

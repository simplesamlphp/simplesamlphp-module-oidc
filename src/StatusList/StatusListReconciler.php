<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListReconciliationCandidate;

/**
 * Catches published Status List Tokens which stopped describing their list.
 *
 * There is one way that can happen. Changing a status is two statements -- update the entry, then clear
 * the list's content hash -- and without transactions a process which dies between them leaves a list
 * whose published token is one revocation too optimistic. The ordering is chosen so that this is the
 * failure that occurs, since the alternative ordering loses the revocation itself, but it still has to
 * be repaired rather than merely tolerated.
 *
 * Each list's published hash is recomputed and compared. Anything which disagrees has its token
 * invalidated, and the next request for that list signs a fresh one. Nothing is signed here: signing on
 * the read path means one signature per list per refresh interval however many changes accumulated,
 * whereas signing here would produce tokens for lists nobody asks for.
 *
 * Note this recomputes rather than comparing timestamps. Entries carry an `updated_at`, so a cheaper
 * filter looked possible -- but allocating an index also stamps it without changing what the list says,
 * so that filter would select almost every list under load while still needing the recomputation to
 * decide anything. The recomputation reads only the entries which are not Valid, over an index which
 * exists for exactly that query, so it is the cheap part already.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\StatusListReconcilerTest
 */
class StatusListReconciler
{
    /** Lists examined per query. */
    protected const int BATCH_SIZE = 100;

    /**
     * Ceiling on the batches one run will work through.
     *
     * Purely a bound on how long one cron run may take. Reaching it is not a normal outcome: every run
     * starts from the beginning, so the lists past the ceiling are examined by no run at all, and a
     * missed invalidation among them would persist. That is why hitting it is reported rather than
     * passed over silently -- it means this needs raising, or the cron running more often.
     */
    protected const int MAX_BATCHES = 1000;


    public function __construct(
        protected readonly StatusListRepository $statusListRepository,
        protected readonly StatusListEntryRepository $statusListEntryRepository,
        protected readonly StatusListContentHasher $statusListContentHasher,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * @return int How many published tokens were found not to describe their list, and invalidated.
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \Exception
     */
    public function reconcile(): int
    {
        // Reading back what was just written is the whole basis of this, so on a SimpleSAMLphp which
        // cannot do that there is nothing safe to do. Status Lists cannot have been enabled either, so
        // there is nothing to reconcile.
        if (!ModuleConfig::hasPrimaryDatabaseReadCapability()) {
            return 0;
        }

        $invalidated = 0;
        $cursor = null;
        $isExhausted = false;

        for ($batch = 0; $batch < self::MAX_BATCHES; $batch++) {
            $statusLists = $this->statusListRepository->findPublished(self::BATCH_SIZE, $cursor);

            if ($statusLists === []) {
                $isExhausted = true;

                break;
            }

            foreach ($statusLists as $statusList) {
                if ($this->isPublishedTokenCurrent($statusList)) {
                    continue;
                }

                // Conditional on the token still being the one examined. A signer may have published a
                // correct token since this batch was read, and clearing that would be churn -- worse,
                // repeated runs could keep defeating a signer which is doing exactly the right thing.
                $wasCleared = $this->statusListRepository->invalidatePublishedTokenIfUnchanged(
                    $statusList->getId(),
                    $statusList->getSignedTokenContentHash(),
                    $statusList->getInvalidationCounter(),
                );

                if (!$wasCleared) {
                    continue;
                }

                $invalidated++;

                $this->loggerService->warning(
                    'A published Status List Token did not describe its list and was invalidated. This ' .
                    'indicates a status change whose invalidation did not complete; the next request ' .
                    'for this list will publish a corrected token.',
                    ['statusListId' => $statusList->getId()],
                );
            }

            // Resume after the last list seen rather than at a numeric offset. Invalidating a list
            // takes it out of the set being paged through, so an offset would step over exactly as many
            // unexamined lists as were invalidated.
            $cursor = $statusLists[array_key_last($statusLists)]->getId();

            if (count($statusLists) < self::BATCH_SIZE) {
                $isExhausted = true;

                break;
            }
        }

        if (!$isExhausted) {
            $this->loggerService->warning(
                sprintf(
                    'Status List reconciliation stopped after %d lists without reaching the end. The ' .
                    'lists beyond that point are examined by no run, since every run starts from the ' .
                    'beginning, so a published token which stopped describing its list would go ' .
                    'uncorrected there until its refresh interval elapses.',
                    self::MAX_BATCHES * self::BATCH_SIZE,
                ),
            );
        }

        return $invalidated;
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function isPublishedTokenCurrent(StatusListReconciliationCandidate $statusList): bool
    {
        return $this->statusListContentHasher->hash(
            $statusList->getBits(),
            $statusList->getCapacity(),
            $this->statusListEntryRepository->findNonValidStatuses($statusList->getId()),
        ) === $statusList->getSignedTokenContentHash();
    }
}

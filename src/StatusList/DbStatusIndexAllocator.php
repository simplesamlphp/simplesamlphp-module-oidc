<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use DateInterval;
use DateTimeImmutable;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Contracts\StatusIndexAllocatorInterface;
use SimpleSAML\Module\oidc\StatusList\Values\AllocationAttempt;
use SimpleSAML\Module\oidc\StatusList\Values\StatusAllocation;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\TokenStatusList;
use Throwable;

/**
 * Claims Status List indices out of pre-seeded rows in the database.
 *
 * Indices are picked at random rather than in sequence. Sequential ones would let anyone holding two
 * credentials, or watching a list fill up, infer roughly when a credential was issued and how many were
 * issued around it, which is the linkability the specification warns about.
 *
 * A pick is a conditional UPDATE which matches only while the index is still free. The number of rows
 * it affected is the whole answer: one means this request got it, zero means someone else did. Nothing
 * has to work out whether an error was a unique constraint violation, which this module could not do
 * reliably anyway, since the database wrapper reports the connection's error rather than the statement's
 * and rethrows without the original.
 *
 * Running out of picks never fails issuance. It means the list is fuller than the counter suggested, so
 * the list is closed, a successor is created, and the credential is allocated there instead. Only being
 * unable to obtain any list at all is an error.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\DbStatusIndexAllocatorTest
 */
class DbStatusIndexAllocator implements StatusIndexAllocatorInterface
{
    /**
     * How full a list is allowed to get before a successor is started.
     *
     * At half full, ten random picks all colliding is around a one in a thousand event, and even then
     * the outcome is a rotation rather than a failure. Pushing this higher makes rotations rarer and
     * collisions common: at 80% full, five picks fail a third of the time.
     */
    protected const float ROTATION_LOAD_FACTOR = 0.5;

    /** Random indices tried in one list before concluding it is too full to bother with. */
    protected const int PROBES_PER_LIST = 10;

    /**
     * Lists tried before giving up entirely. Each attempt either allocates or rotates, so more than a
     * couple of rounds means something is wrong that retrying will not fix.
     */
    protected const int MAX_LIST_ATTEMPTS = 3;

    /** Generations tried when another request keeps winning the race to create the successor. */
    protected const int MAX_CREATE_ATTEMPTS = 3;

    /**
     * How long to wait, in total, for a list another request is still seeding.
     *
     * Seeding a default sized list is a few hundred batched inserts, so this is normally over in well
     * under a second. Waiting rather than starting a second list keeps a pool's lane to one list, which
     * is what herd privacy depends on. If the wait runs out, the caller starts its own list instead --
     * a wasted list is a privacy cost, but failing to issue a credential is worse.
     */
    protected const int PREPARING_LIST_WAIT_ATTEMPTS = 20;

    protected const int PREPARING_LIST_WAIT_MICROSECONDS = 250000;

    /**
     * Past this age, a list which is still not open is taken to have been abandoned by a request which
     * died partway through seeding it. Without this, one such list would make every later request wait
     * out the full budget before getting on with its own.
     */
    protected const string PREPARING_LIST_STALE_AFTER = 'PT2M';


    public function __construct(
        protected readonly StatusListRepository $statusListRepository,
        protected readonly StatusListEntryRepository $statusListEntryRepository,
        protected readonly StatusListKeyResolver $statusListKeyResolver,
        protected readonly TokenStatusList $tokenStatusList,
        protected readonly Routes $routes,
        protected readonly Helpers $helpers,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     * @throws \JsonException
     * @throws \Exception
     */
    public function allocateFor(
        StatusListPool $pool,
        string $credentialId,
        string $credentialConfigurationId,
        ?string $subjectRef = null,
        ?DateTimeImmutable $expiresAt = null,
    ): StatusAllocation {
        $signingKeyId = $this->statusListKeyResolver->getCurrentKeyId();
        $policyFingerprint = $pool->getPolicyFingerprint($signingKeyId);

        // Decided once, here, from the expiry this credential is being issued with, and carried through
        // every lookup below. A list which never expires can never be retired, so it must not share a
        // list with credentials which do -- see StatusListExpiryLaneEnum.
        $expiryLane = StatusListExpiryLaneEnum::forExpiry($expiresAt);

        $allocationAttempt = new AllocationAttempt();

        for ($attempt = 1; $attempt <= self::MAX_LIST_ATTEMPTS; $attempt++) {
            $statusList = $this->selectList(
                $pool,
                $policyFingerprint,
                $expiryLane,
                $signingKeyId,
                $allocationAttempt,
            );

            $allocation = $this->tryAllocateIn(
                $statusList,
                $credentialId,
                $credentialConfigurationId,
                $subjectRef,
                $expiresAt,
            );

            if ($allocation instanceof StatusAllocation) {
                // The index is claimed and the linkage is written, so the credential can be issued.
                // The counter is advisory and allowed to undercount, so failing to bump it must not
                // undo that: throwing here would lose an index which is already durably taken, and a
                // retry of the same credential would then collide on its unique hash.
                try {
                    $this->statusListRepository->incrementAllocatedCount($statusList->getId());
                } catch (Throwable $throwable) {
                    $this->loggerService->warning(
                        'Could not update the Status List allocation counter, which only affects when ' .
                        'the list is rotated.',
                        ['statusListId' => $statusList->getId(), 'error' => $throwable->getMessage()],
                    );
                }

                $this->loggerService->debug(
                    'Allocated a Status List index.',
                    [
                        'statusListId' => $statusList->getId(),
                        'idx' => $allocation->getIdx(),
                        'poolId' => $pool->getId(),
                        'expiryLane' => $expiryLane->value,
                        'credentialConfigurationId' => $credentialConfigurationId,
                    ],
                );

                return $allocation;
            }

            // Every pick collided, or the list stopped accepting allocations while we were picking.
            // Either way this list is done; close it so the next round starts a successor.
            $this->loggerService->info(
                'Status List did not yield a free index, rotating to a successor.',
                [
                    'statusListId' => $statusList->getId(),
                    'poolId' => $pool->getId(),
                    'expiryLane' => $expiryLane->value,
                    'attempt' => $attempt,
                ],
            );

            $this->statusListRepository->deactivate($statusList->getId());
        }

        throw new StatusListException(
            sprintf(
                'Unable to allocate a Status List index for pool "%s" in the "%s" lane after %d attempts.',
                $pool->getId(),
                $expiryLane->value,
                self::MAX_LIST_ATTEMPTS,
            ),
        );
    }


    /**
     * A list of this pool and lane which is accepting allocations, creating one if there is none.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \JsonException
     * @throws \Exception
     */
    protected function selectList(
        StatusListPool $pool,
        string $policyFingerprint,
        StatusListExpiryLaneEnum $expiryLane,
        string $signingKeyId,
        AllocationAttempt $allocationAttempt,
    ): StatusListRecord {
        $openList = $this->findOpenListWithRoom($pool, $policyFingerprint, $expiryLane);

        if ($openList instanceof StatusListRecord) {
            return $openList;
        }

        // Nothing open, but another request may already be seeding one. Joining it rather than starting
        // a second list is what keeps a lane to one list, which is what its credentials hide in.
        $preparedList = $this->awaitListBeingPrepared(
            $pool,
            $policyFingerprint,
            $expiryLane,
            $allocationAttempt,
        );

        if ($preparedList instanceof StatusListRecord) {
            return $preparedList;
        }

        return $this->createList(
            $pool,
            $policyFingerprint,
            $expiryLane,
            $signingKeyId,
            $allocationAttempt,
        );
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function findOpenListWithRoom(
        StatusListPool $pool,
        string $policyFingerprint,
        StatusListExpiryLaneEnum $expiryLane,
    ): ?StatusListRecord {
        $candidates = $this->statusListRepository->findActiveForPolicy(
            $pool->getId(),
            $policyFingerprint,
            $expiryLane,
        );

        // Chosen in PHP rather than with ORDER BY RANDOM(), whose spelling differs between the drivers
        // this module supports.
        shuffle($candidates);

        $full = [];

        foreach ($candidates as $candidate) {
            if ($this->hasRoom($candidate)) {
                return $candidate;
            }

            $full[] = $candidate;
        }

        // Nothing here has room, so these are done. Closing them now rather than merely stepping over
        // them keeps them out of every later candidate query, stops a worker holding a stale selection
        // from still allocating into one, and starts the clock which retirement waits on. The counter
        // can undercount but never overcount, so a list which reads as full really is at least that
        // full and closing it is safe.
        foreach ($full as $candidate) {
            $this->statusListRepository->deactivate($candidate->getId());
        }

        return null;
    }


    /**
     * Waits, for a bounded time, on a list another request is still seeding.
     *
     * Returns null when there is nothing to wait for, or when the wait ran out. Both mean the same
     * thing to the caller: get on with creating a list of its own. Running out is not treated as an
     * error, because a wasted list costs herd privacy while a failed allocation costs the credential.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \Exception
     */
    protected function awaitListBeingPrepared(
        StatusListPool $pool,
        string $policyFingerprint,
        StatusListExpiryLaneEnum $expiryLane,
        AllocationAttempt $allocationAttempt,
    ): ?StatusListRecord {
        // Waited once already and got nothing, so whoever holds that list is not coming back. Waiting
        // again would just spend another budget arriving at the same answer.
        if ($allocationAttempt->hasWaitedInVain()) {
            return null;
        }

        if (!$this->isListBeingPrepared($pool, $policyFingerprint, $expiryLane)) {
            return null;
        }

        $this->loggerService->debug(
            'Waiting for a Status List another request is preparing.',
            ['poolId' => $pool->getId(), 'expiryLane' => $expiryLane->value],
        );

        for ($attempt = 0; $attempt < self::PREPARING_LIST_WAIT_ATTEMPTS; $attempt++) {
            usleep(self::PREPARING_LIST_WAIT_MICROSECONDS);

            $openList = $this->findOpenListWithRoom($pool, $policyFingerprint, $expiryLane);

            if ($openList instanceof StatusListRecord) {
                return $openList;
            }

            // The other request gave up, died, or its list went straight to being closed. Either way
            // there is no longer anything to wait for.
            if (!$this->isListBeingPrepared($pool, $policyFingerprint, $expiryLane)) {
                return null;
            }
        }

        $this->loggerService->warning(
            'Gave up waiting for a Status List another request is preparing, creating one instead.',
            ['poolId' => $pool->getId(), 'expiryLane' => $expiryLane->value],
        );

        // Recorded only when the budget actually ran out with the list still unfinished, which is what
        // distinguishes a creator that is merely slow from one that is gone.
        $allocationAttempt->recordWaitedInVain();

        return null;
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \Exception
     */
    protected function isListBeingPrepared(
        StatusListPool $pool,
        string $policyFingerprint,
        StatusListExpiryLaneEnum $expiryLane,
    ): bool {
        return $this->statusListRepository->findBeingPreparedForPolicy(
            $pool->getId(),
            $policyFingerprint,
            $expiryLane,
            $this->staleBefore(),
        ) !== [];
    }


    /**
     * Whether the list this request has just created turned out to be redundant.
     *
     * Two cases, and both have to be asked about because the unique constraint the insert was settled by
     * only settles a race between requests which picked the *same* generation. Two requests which read
     * the highest generation a moment apart pick different ones, so both inserts succeed and nothing
     * collides.
     *
     * Deliberately not phrased as "does any earlier list exist": a list which is open but full is
     * earlier and is not a reason to stand down, since it is exactly what this request is replacing.
     *
     * Both questions are asked within this request's own lane, and that is not incidental. Standing down
     * means adopting the other request's list, so standing down for a list in the other lane would be
     * standing aside for something this request can never use -- and, worse, the adoption which follows
     * could then hand back that other lane's open list, whose every index this request's allocation is
     * refused by, leaving the allocator to read the refusals as a full list and deactivate a perfectly
     * good one belonging to the other lane.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \Exception
     */
    protected function isSupersededAfterCreating(
        StatusListPool $pool,
        string $policyFingerprint,
        StatusListExpiryLaneEnum $expiryLane,
        int $generation,
    ): bool {
        // Someone else's list became open while this request was inserting its own.
        if ($this->findOpenListWithRoom($pool, $policyFingerprint, $expiryLane) instanceof StatusListRecord) {
            return true;
        }

        // Someone else is seeding an earlier generation. Exactly one request holds the lowest, so
        // exactly one carries on and the rest stand down.
        return $this->statusListRepository->findBeingPreparedForPolicy(
            $pool->getId(),
            $policyFingerprint,
            $expiryLane,
            $this->staleBefore(),
            $generation,
        ) !== [];
    }


    /**
     * The point past which a list which is still not open counts as abandoned rather than in progress.
     *
     * @throws \Exception
     */
    protected function staleBefore(): DateTimeImmutable
    {
        return $this->helpers->dateTime()->getUtc()
            ->sub(new DateInterval(self::PREPARING_LIST_STALE_AFTER));
    }


    /**
     * Whether a list is below the point at which a successor should be started.
     *
     * The counter this reads can undercount, since it is bumped by a statement separate from the
     * allocation itself. That is tolerable precisely because running out of picks rotates: the counter
     * only decides when to rotate early, never whether allocation can succeed.
     */
    protected function hasRoom(StatusListRecord $statusList): bool
    {
        return $statusList->getAllocatedCount() < (int)floor(
            (float)$statusList->getCapacity() * self::ROTATION_LOAD_FACTOR,
        );
    }


    /**
     * Creates a list, seeds every index, and opens it for allocation.
     *
     * The unique constraint on (pool_id, policy_fingerprint, expiry_lane, generation) settles a race
     * between two requests both deciding a successor is needed: one insert wins. The loser does not need
     * to establish *why* its insert failed -- and could not reliably -- because the recovery is the same
     * whatever the reason: look again and use whichever list is open now.
     *
     * That the constraint is scoped to the policy and the lane, and not merely to the pool, is what makes
     * the recovery sound. A collision is only worth settling between two requests which would use the
     * same list; the loser of a collision across policies or lanes could not adopt the winner's list at
     * all, since its own lookups filter that list out, so it would find nothing and spend one of its
     * bounded creation attempts for nothing.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \JsonException
     * @throws \Exception
     */
    protected function createList(
        StatusListPool $pool,
        string $policyFingerprint,
        StatusListExpiryLaneEnum $expiryLane,
        string $signingKeyId,
        AllocationAttempt $allocationAttempt,
        int $attempt = 1,
    ): StatusListRecord {
        $id = hash('sha256', $this->helpers->random()->getIdentifier());
        $generation = $this->statusListRepository->getHighestGeneration(
            $pool->getId(),
            $policyFingerprint,
            $expiryLane,
        ) + 1;

        // Minted once, here, and stored. Everything downstream uses the stored string rather than
        // rebuilding it, because a Relying Party rejects a Status List Token whose subject is not byte
        // for byte the URI the credential named.
        $uri = $this->routes->urlStatusList($id);

        try {
            $this->statusListRepository->create(
                $id,
                $uri,
                $pool->getId(),
                $policyFingerprint,
                $expiryLane,
                $generation,
                $pool->getBits(),
                $pool->getCapacity(),
                $pool->getAllowedStatusesAsString(),
                $pool->getTtlInSeconds(),
                $pool->getTokenValidityInSeconds(),
                $pool->getRefreshIntervalInSeconds(),
                $signingKeyId,
                $pool->getKeyProfile(),
            );
        } catch (Throwable $throwable) {
            $this->loggerService->info(
                'Could not create a Status List, checking whether another request already did.',
                [
                    'poolId' => $pool->getId(),
                    'expiryLane' => $expiryLane->value,
                    'generation' => $generation,
                    'error' => $throwable->getMessage(),
                ],
            );

            return $this->adoptListCreatedByAnotherRequest(
                $pool,
                $policyFingerprint,
                $expiryLane,
                $signingKeyId,
                $allocationAttempt,
                $attempt,
                $throwable,
            );
        }

        // Standing down means waiting on somebody else's list, so a request which has already waited in
        // vain must not do it again: what it is looking at is a list nobody is going to finish. It
        // takes over instead, at a cost of one surplus list, rather than deleting its own, waiting, and
        // repeating until it ran out of attempts and failed the issuance.
        if (
            !$allocationAttempt->hasWaitedInVain() &&
            $this->isSupersededAfterCreating($pool, $policyFingerprint, $expiryLane, $generation)
        ) {
            $this->loggerService->info(
                'Another request already produced a Status List for this pool and lane, standing down.',
                [
                    'statusListId' => $id,
                    'poolId' => $pool->getId(),
                    'expiryLane' => $expiryLane->value,
                    'generation' => $generation,
                ],
            );

            $this->statusListRepository->deleteUnopened($id);

            return $this->adoptListCreatedByAnotherRequest(
                $pool,
                $policyFingerprint,
                $expiryLane,
                $signingKeyId,
                $allocationAttempt,
                $attempt,
                new StatusListException('Superseded by a Status List of a lower generation.'),
            );
        }

        // The list is inactive until this finishes, so nothing can pick an index which does not exist
        // yet. A crash partway leaves an inactive list nothing points at, which is inert rather than
        // harmful.
        $this->statusListEntryRepository->seed($id, $pool->getCapacity());
        $this->statusListRepository->activate($id);

        $statusList = $this->statusListRepository->findByIdOnPrimary($id);

        if (!$statusList instanceof StatusListRecord) {
            throw new StatusListException(
                sprintf('Status List "%s" was created but could not be read back.', $id),
            );
        }

        $this->loggerService->info(
            'Created a Status List.',
            [
                'statusListId' => $id,
                'poolId' => $pool->getId(),
                'expiryLane' => $expiryLane->value,
                'generation' => $generation,
                'capacity' => $pool->getCapacity(),
            ],
        );

        return $statusList;
    }


    /**
     * Recovers from an insert which did not succeed.
     *
     * The cause is deliberately not examined. The database wrapper reports the connection's error
     * rather than the failing statement's and rethrows without the original, so a lost race for a
     * generation can not be reliably told apart from anything else -- and it does not need to be,
     * because the recovery is the same either way: use whichever list the winner produced, waiting for
     * it if it is still being seeded, and start the next generation if there is nothing to wait for.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \JsonException
     * @throws \Exception
     */
    protected function adoptListCreatedByAnotherRequest(
        StatusListPool $pool,
        string $policyFingerprint,
        StatusListExpiryLaneEnum $expiryLane,
        string $signingKeyId,
        AllocationAttempt $allocationAttempt,
        int $attempt,
        Throwable $cause,
    ): StatusListRecord {
        // The winner is very often still seeding at this point -- that is the whole reason this
        // request's own insert lost -- so waiting here is what actually makes the lane converge on one
        // list. It is a no-op once this request has already waited in vain, which is what stops a dead
        // creator from costing a wait on every attempt.
        $adopted = $this->findOpenListWithRoom($pool, $policyFingerprint, $expiryLane)
        ?? $this->awaitListBeingPrepared($pool, $policyFingerprint, $expiryLane, $allocationAttempt);

        if ($adopted instanceof StatusListRecord) {
            return $adopted;
        }

        // Nothing to adopt, so the generation this request picked is taken but produced no usable list.
        // Trying again recomputes it, which is what lets this make progress rather than fail outright.
        if ($attempt < self::MAX_CREATE_ATTEMPTS) {
            return $this->createList(
                $pool,
                $policyFingerprint,
                $expiryLane,
                $signingKeyId,
                $allocationAttempt,
                $attempt + 1,
            );
        }

        throw new StatusListException(
            sprintf(
                'Unable to create a Status List for pool "%s" in the "%s" lane after %d attempts, and ' .
                'no other list is available: %s',
                $pool->getId(),
                $expiryLane->value,
                $attempt,
                $cause->getMessage(),
            ),
            (int)$cause->getCode(),
            $cause,
        );
    }


    /**
     * Tries random indices in one list until one is free or the budget runs out.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     * @throws \SimpleSAML\OpenID\Exceptions\StatusListException
     * @throws \Exception
     */
    protected function tryAllocateIn(
        StatusListRecord $statusList,
        string $credentialId,
        string $credentialConfigurationId,
        ?string $subjectRef,
        ?DateTimeImmutable $expiresAt,
    ): ?StatusAllocation {
        $capacity = $statusList->getCapacity();

        if ($capacity < 1) {
            return null;
        }

        $tried = [];

        for ($probe = 0; $probe < self::PROBES_PER_LIST; $probe++) {
            $idx = random_int(0, $capacity - 1);

            // Retrying an index already known to be taken would waste part of the budget.
            if (isset($tried[$idx])) {
                continue;
            }

            $tried[$idx] = true;

            $isAllocated = $this->statusListEntryRepository->allocate(
                $statusList->getId(),
                $idx,
                $credentialId,
                $this->statusListEntryRepository->hashCredentialId($credentialId),
                $credentialConfigurationId,
                $subjectRef,
                $expiresAt,
            );

            if ($isAllocated) {
                return new StatusAllocation(
                    $statusList->getId(),
                    $this->tokenStatusList->statusReferenceFactory()->build($statusList->getUri(), $idx),
                );
            }
        }

        return null;
    }
}

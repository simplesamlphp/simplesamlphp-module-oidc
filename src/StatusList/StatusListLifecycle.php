<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusAuditRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListAllocationTarget;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListLifecycleReport;
use Throwable;

/**
 * Everything a Status List needs done to it which nothing else asks for.
 *
 * The issuance and revocation paths only ever move forwards: they allocate an index, change a status,
 * publish a token. Nothing on them has a reason to notice that a credential expired last week, or that a
 * list which filled up two years ago is still being served for the sake of credentials which all lapsed.
 * That noticing is what this does, from the cron hook.
 *
 * A list goes through four states and this drives the last three of them:
 *
 *  1. **Active** -- new credentials are allocated into it. The allocator deactivates a list once it is
 *     full; this deactivates the ones which stopped being allocation targets for the other reason, which
 *     is that the configuration they were created under is no longer the current one.
 *  2. **Deactivated** -- still served, no longer allocated into, waiting for the credentials inside it to
 *     expire. Most of a list's life is spent here, and for a list in the non-expiring lane, all of it.
 *  3. **Retired** -- every credential in it expired, a grace period passed on top, and the list stopped
 *     being served. Its published token is given back at this point.
 *  4. **Emptied** -- the hundred thousand entry rows behind a retired list are removed, over as many runs
 *     as the bound takes.
 *
 * Running alongside all of that, and unrelated to it: the linkage recording which credential holds which
 * index is deleted once that credential expires, and the audit trail is pruned to whatever retention the
 * deployment has set.
 *
 * Every step here is bounded, and none of them has to finish in one run. What one run leaves undone the
 * next one picks up, so the cost of a cron which runs too rarely is a backlog rather than a failure.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\StatusListLifecycleTest
 */
class StatusListLifecycle
{
    /**
     * Rows whose linkage is cleared per round of the loop.
     *
     * A round's size, not a statement's. How many rows one statement can name is a question about what
     * the drivers allow, which the repository answers by splitting the rows it is handed; this only
     * decides how much work a round asks for and therefore how often the loop looks again. It sits under
     * a single statement's worth as it happens, so a round is normally one update.
     */
    protected const int LINKAGE_BATCH_SIZE = 400;

    /**
     * Ceiling on the linkage clearing one run will do.
     *
     * Deliberately generous. Reaching it is not a failure -- the remainder is cleared by the next run --
     * but the rows in the backlog are ones which should already have been forgotten, so the ceiling is
     * set where a deployment which has just switched credential expiry on works through its first day's
     * worth in one go rather than over a week of cron runs.
     */
    protected const int MAX_LINKAGE_BATCHES = 200;

    /** Lists examined for retirement per query. */
    protected const int RETIREMENT_BATCH_SIZE = 100;

    /** Ceiling on how many batches of retirement candidates one run will work through. */
    protected const int MAX_RETIREMENT_BATCHES = 100;

    /** Retired lists whose entries one run will work at. */
    protected const int PURGE_LIST_LIMIT = 10;

    /** Entry rows removed per statement. */
    protected const int PURGE_BATCH_SIZE = 1000;

    /**
     * Ceiling on entry rows removed per retired list per run.
     *
     * A list at the default capacity has 131072 entries, so this clears one over a handful of runs
     * rather than in a single cron invocation which holds the table busy for the duration. Nothing is
     * waiting on it: the list stopped being served the moment it was retired.
     */
    protected const int MAX_PURGED_ENTRIES_PER_LIST = 20000;

    /** Audit rows removed per round of the loop. */
    protected const int AUDIT_BATCH_SIZE = 500;

    /** Ceiling on how many batches of audit rows one run will remove. */
    protected const int MAX_AUDIT_BATCHES = 200;


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly StatusListRepository $statusListRepository,
        protected readonly StatusListEntryRepository $statusListEntryRepository,
        protected readonly StatusAuditRepository $statusAuditRepository,
        protected readonly StatusListKeyResolver $statusListKeyResolver,
        protected readonly Helpers $helpers,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * Runs every step, and lets each of them fail on its own.
     *
     * The steps share tables but not purposes, and one of them -- deleting the linkage of credentials
     * which have expired -- is an undertaking made to the people those credentials name. Letting a
     * failure in the audit prune abandon the rest of the run would quietly suspend that undertaking for
     * as long as the failure lasted, so each step is attempted regardless of how its neighbours went and
     * what went wrong is reported rather than raised.
     */
    public function run(): StatusListLifecycleReport
    {
        // Reading back what was just written is what Status Lists are built on, so a SimpleSAMLphp which
        // cannot do it can never have had them enabled, and there is nothing here to maintain.
        if (!ModuleConfig::hasPrimaryDatabaseReadCapability()) {
            return new StatusListLifecycleReport();
        }

        $failures = [];

        $clearedLinkages = $this->attempt(
            'Clearing the linkage of expired credentials',
            fn(): int => $this->clearExpiredCredentialLinkage(),
            $failures,
        );
        $deactivatedStatusLists = $this->attempt(
            'Deactivating superseded Status Lists',
            fn(): int => $this->deactivateSupersededStatusLists(),
            $failures,
        );
        $retiredStatusLists = $this->attempt(
            'Retiring spent Status Lists',
            fn(): int => $this->retireSpentStatusLists(),
            $failures,
        );
        // Which never touches a list retired in the step above: this one waits out a further grace
        // period before removing anything, so its ordering here is a matter of reading rather than of
        // what it does.
        $purgedEntries = $this->attempt(
            'Removing the entries of retired Status Lists',
            fn(): int => $this->purgeRetiredStatusListEntries(),
            $failures,
        );
        $prunedAuditRows = $this->attempt(
            'Pruning the status audit trail',
            fn(): int => $this->pruneStatusAuditTrail(),
            $failures,
        );

        return new StatusListLifecycleReport(
            $clearedLinkages,
            $deactivatedStatusLists,
            $retiredStatusLists,
            $purgedEntries,
            $prunedAuditRows,
            $failures,
        );
    }


    /**
     * Runs one step, and turns anything it throws into something the caller can carry on past.
     *
     * @param callable():int $step
     * @param string[] $failures Appended to when the step does not complete.
     */
    protected function attempt(string $description, callable $step, array &$failures): int
    {
        try {
            return $step();
        } catch (Throwable $throwable) {
            $failure = sprintf('%s failed: %s', $description, $throwable->getMessage());
            $failures[] = $failure;
            $this->loggerService->error('Status List lifecycle: ' . $failure);

            return 0;
        }
    }


    /**
     * Forgets which credential held which index, once that credential has expired.
     *
     * The index and the status it ended on stay. Those are what the published token is built from, and
     * what stops the index being handed out to a second credential -- but they say nothing about who was
     * issued what, which is the part which is not kept a moment longer than revoking the credential
     * required.
     *
     * @return int How many rows were cleared.
     * @throws \Exception
     */
    public function clearExpiredCredentialLinkage(): int
    {
        $now = $this->helpers->dateTime()->getUtc();
        $cleared = 0;

        for ($batch = 0; $batch < self::MAX_LINKAGE_BATCHES; $batch++) {
            $inBatch = $this->statusListEntryRepository->clearExpiredLinkage($now, self::LINKAGE_BATCH_SIZE);
            $cleared += $inBatch;

            if ($inBatch < self::LINKAGE_BATCH_SIZE) {
                return $cleared;
            }
        }

        $this->loggerService->info(
            sprintf(
                'Status List lifecycle cleared the linkage of %d expired credential(s) and stopped at ' .
                'its ceiling for one run. The rest is cleared by the next run.',
                $cleared,
            ),
        );

        return $cleared;
    }


    /**
     * Stops lists being allocation targets when the configuration they were created under is no longer
     * the current one.
     *
     * A list is only selected for allocation while its pool, policy fingerprint and expiry lane all match
     * something the module is configured to produce now, so changing a pool's settings, rotating the
     * signing key, or changing which of a pool's credential configurations have a lifetime silently
     * retires a list from service without recording that anything happened to it. Nothing would ever fill
     * it, so nothing would ever deactivate it, and every later step begins with deactivation.
     *
     * The lane has to be part of that comparison, and it is the one part which is not a property of the
     * pool. Removing the last credential lifetime covering a pool leaves its policy fingerprint
     * unchanged while routing every new credential to the other lane, so a comparison of pool and policy
     * alone would leave the old list active, reachable by nothing, and served for ever -- which is
     * exactly the outcome expiry lanes exist to prevent, arrived at from the other direction.
     *
     * This asks configuration what a lane should be, where allocation asks the credential's own expiry.
     * The two answer different questions and both are needed, but they can disagree if the nodes serving
     * issuance and the node running cron read different configuration. That is waste, not corruption: the
     * allocating statement refuses a deactivated list, and retirement re-checks the actual entry expiries
     * in the statement which retires. It is waste which repeats, though -- each run deactivates the lane
     * stale workers keep allocating into, and their next allocation creates another list -- so the two
     * kinds of supersession are reported separately below, and a deployment is expected to keep its
     * configuration coherent.
     *
     * Skipped entirely while Status Lists are switched off. An operator who has turned the feature off
     * for a moment has not asked for every list they have to start winding down, and turning it back on
     * would not undo it.
     *
     * @return int How many lists were deactivated.
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \Exception
     */
    public function deactivateSupersededStatusLists(): int
    {
        if (!$this->moduleConfig->getVciStatusListEnabled()) {
            return 0;
        }

        $signingKeyId = $this->statusListKeyResolver->getCurrentKeyId();
        $currentTargets = [];

        foreach ($this->moduleConfig->getVciStatusListPoolBag()->getAll() as $pool) {
            $policyFingerprint = $pool->getPolicyFingerprint($signingKeyId);

            foreach ($this->moduleConfig->getVciStatusListCurrentLanesFor($pool) as $expiryLane) {
                $currentTargets[] = new StatusListAllocationTarget(
                    $pool->getId(),
                    $policyFingerprint,
                    $expiryLane,
                );
            }
        }

        $deactivated = $this->statusListRepository->deactivateSuperseded($currentTargets);

        if ($deactivated > 0) {
            $this->loggerService->info(
                sprintf(
                    'Status List lifecycle deactivated %d Status List(s) which the current configuration ' .
                    'would no longer allocate into. They go on being served until every credential in ' .
                    'them has expired.',
                    $deactivated,
                ),
            );

            $this->warnIfLanesAreBeingSuperseded($currentTargets);
        }

        return $deactivated;
    }


    /**
     * Says so when a pool has stopped using one of the two expiry lanes.
     *
     * Ordinarily this is a one-off: an operator gave a credential configuration a lifetime, or took one
     * away, and the list of the lane that configuration used to route to is deactivated once and retires
     * on its own schedule. Nothing needs doing about it, but it is worth being able to see, because the
     * same message arriving on run after run means something else -- the issuing nodes are still
     * allocating into that lane, so they are reading different configuration from this one, and each run
     * is deactivating a list they then immediately replace. In the non-expiring lane those replacements
     * are never retired.
     *
     * Reported separately from a policy supersession for that reason: a fingerprint change is
     * self-limiting, while this one can repeat indefinitely without anything else complaining.
     *
     * @param \SimpleSAML\Module\oidc\StatusList\Values\StatusListAllocationTarget[] $currentTargets
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function warnIfLanesAreBeingSuperseded(array $currentTargets): void
    {
        $lanesByPoolId = [];

        foreach ($currentTargets as $currentTarget) {
            $lanesByPoolId[$currentTarget->getPoolId()][] = $currentTarget->getExpiryLane()->value;
        }

        foreach ($lanesByPoolId as $poolId => $lanes) {
            if (count($lanes) > 1) {
                continue;
            }

            $this->loggerService->info(
                sprintf(
                    'Status List pool "%s" currently allocates only into the "%s" expiry lane, so any ' .
                    'list it has in the other lane is no longer an allocation target. If this is ' .
                    'reported on every run while credentials are still being issued, the nodes serving ' .
                    'issuance and the node running cron are reading different configuration, and each ' .
                    'run is deactivating a list they replace.',
                    $poolId,
                    $lanes[0] ?? '',
                ),
            );
        }
    }


    /**
     * Retires the lists which nothing can still be holding.
     *
     * Two waits have to have elapsed, and they are the same length because they ask the same question.
     * The first runs from the moment the list stopped accepting allocations, which covers an issuance
     * which was in flight at that moment. The second runs from the expiry of the last credential in the
     * list, which covers a Relying Party still working from a response it cached, or a wallet presenting
     * a credential it has not noticed is expired.
     *
     * A list holding even one credential without an expiry is never retired, however long it waits. Since
     * such credentials are allocated into a lane of their own, that is now normally a whole list of them
     * rather than one credential holding up a list of others.
     *
     * @return int How many lists were retired.
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \Exception
     */
    public function retireSpentStatusLists(): int
    {
        $grace = $this->moduleConfig->getVciStatusListRetirementGrace();
        $now = $this->helpers->dateTime()->getUtc();
        $graceExpiredBefore = $now->sub($grace);

        $retired = 0;
        $cursor = null;
        $isExhausted = false;

        for ($batch = 0; $batch < self::MAX_RETIREMENT_BATCHES; $batch++) {
            $candidateIds = $this->statusListRepository->findRetirementCandidates(
                $graceExpiredBefore,
                self::RETIREMENT_BATCH_SIZE,
                $cursor,
            );

            if ($candidateIds === []) {
                $isExhausted = true;

                break;
            }

            foreach ($candidateIds as $candidateId) {
                // Whether the list has anything left in it is decided by the statement which retires
                // it, not here. Reading the entries first and retiring second would leave a gap an
                // issuance already in flight could land in, and there are no transactions to close it
                // with -- so the list simply matches no rows if it stopped qualifying.
                if (!$this->statusListRepository->retire($candidateId, $graceExpiredBefore)) {
                    continue;
                }

                $retired++;

                $this->loggerService->info(
                    'A Status List was retired and no longer answers requests. Every credential issued ' .
                    'from it had expired, and the retirement grace period had passed on top of that.',
                    ['statusListId' => $candidateId],
                );
            }

            // Resume after the last list seen rather than at a numeric offset. Retiring a list takes it
            // out of the set being paged through, so an offset would step over exactly as many
            // unexamined lists as were retired.
            $cursor = $candidateIds[array_key_last($candidateIds)];

            if (count($candidateIds) < self::RETIREMENT_BATCH_SIZE) {
                $isExhausted = true;

                break;
            }
        }

        if (!$isExhausted) {
            $this->loggerService->warning(
                sprintf(
                    'Status List retirement stopped after %d lists without reaching the end. Every run ' .
                    'starts from the beginning, so the lists beyond that point are examined by no run ' .
                    'at all and will not be retired until the ones before them are.',
                    self::MAX_RETIREMENT_BATCHES * self::RETIREMENT_BATCH_SIZE,
                ),
            );
        }

        return $retired;
    }


    /**
     * Removes the entry rows of lists which have been retired.
     *
     * This is where retirement gets anything back. Retiring a list gives up its published token, which is
     * a couple of hundred kilobytes; the entries behind it are a row per index, which at the default
     * capacity is a hundred and thirty thousand of them, and they are why leaving credential expiry
     * switched off means storage that only ever grows.
     *
     * Safe only because the list is retired. Entries are otherwise kept for the whole life of the list
     * however long ago the credential in them expired, since an index which was handed out once must
     * never be handed out again -- but a retired list is neither served nor allocated into, so its
     * indices can not be handed out at all.
     *
     * A list retired a moment ago is left alone even so. Retirement can not be serialised against an
     * issuance which was already in flight, so a credential can in principle be written into a list just
     * after it was retired; retirement alone leaves that credential unverifiable, while removing the
     * entries as well would leave nothing to show it was ever issued. The rows stay until the same wait
     * which precedes retirement has passed again.
     *
     * @return int How many entry rows were removed.
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \Exception
     */
    public function purgeRetiredStatusListEntries(): int
    {
        $purged = 0;
        $retiredBefore = $this->helpers->dateTime()->getUtc()
            ->sub($this->moduleConfig->getVciStatusListRetirementGrace());

        $statusListIds = $this->statusListRepository->findRetiredWithEntries(
            self::PURGE_LIST_LIMIT,
            $retiredBefore,
        );

        foreach ($statusListIds as $statusListId) {
            $purgedForList = 0;

            while ($purgedForList < self::MAX_PURGED_ENTRIES_PER_LIST) {
                $inBatch = $this->statusListEntryRepository->deleteRetiredEntries(
                    $statusListId,
                    self::PURGE_BATCH_SIZE,
                );

                if ($inBatch < 1) {
                    break;
                }

                $purgedForList += $inBatch;
            }

            $purged += $purgedForList;
        }

        return $purged;
    }


    /**
     * Prunes the status audit trail to the configured retention.
     *
     * Absent by default, in which case nothing is removed. How long a record of who revoked what needs
     * keeping is a question about the deployment's own obligations rather than one this module can
     * answer, and the trail is a row per status change rather than a row per credential, so keeping it
     * indefinitely costs little in storage. It is not free of personal data, though: the credential
     * appears only as a hash, but the actor is recorded as given, and where the admin authentication
     * source releases an identifier that names a person. Which is the other reason to set a retention.
     *
     * @return int How many rows were removed.
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \Exception
     */
    public function pruneStatusAuditTrail(): int
    {
        $retention = $this->moduleConfig->getVciStatusListAuditRetention();

        if ($retention === null) {
            return 0;
        }

        $createdBefore = $this->helpers->dateTime()->getUtc()->sub($retention);
        $pruned = 0;

        for ($batch = 0; $batch < self::MAX_AUDIT_BATCHES; $batch++) {
            $inBatch = $this->statusAuditRepository->removeOlderThan($createdBefore, self::AUDIT_BATCH_SIZE);
            $pruned += $inBatch;

            if ($inBatch < self::AUDIT_BATCH_SIZE) {
                return $pruned;
            }
        }

        return $pruned;
    }
}

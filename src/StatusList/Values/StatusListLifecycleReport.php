<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

/**
 * What one lifecycle run got through.
 *
 * Every step is bounded, so these counts are as much a signal about pacing as about work done: a run
 * which keeps reporting a full batch is one whose cron is not running often enough to keep up with what
 * is coming due.
 *
 * Failures are carried rather than thrown because the steps are independent obligations. Deleting the
 * linkage of expired credentials is a promise made to the people those credentials were issued to, and
 * it should not be skipped for a year because pruning an audit trail keeps failing.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\Values\StatusListLifecycleReportTest
 */
class StatusListLifecycleReport
{
    /**
     * @param string[] $failures One entry per step which did not complete, already phrased for an
     * operator reading a cron summary.
     */
    public function __construct(
        protected readonly int $clearedLinkages = 0,
        protected readonly int $deactivatedStatusLists = 0,
        protected readonly int $retiredStatusLists = 0,
        protected readonly int $purgedEntries = 0,
        protected readonly int $prunedAuditRows = 0,
        protected readonly array $failures = [],
    ) {
    }


    public function getClearedLinkages(): int
    {
        return $this->clearedLinkages;
    }


    public function getDeactivatedStatusLists(): int
    {
        return $this->deactivatedStatusLists;
    }


    public function getRetiredStatusLists(): int
    {
        return $this->retiredStatusLists;
    }


    public function getPurgedEntries(): int
    {
        return $this->purgedEntries;
    }


    public function getPrunedAuditRows(): int
    {
        return $this->prunedAuditRows;
    }


    /**
     * @return string[]
     */
    public function getFailures(): array
    {
        return $this->failures;
    }


    /**
     * Whether the run changed anything at all, so that a cron which has nothing to do stays quiet.
     */
    public function hasChanges(): bool
    {
        return $this->clearedLinkages > 0 ||
        $this->deactivatedStatusLists > 0 ||
        $this->retiredStatusLists > 0 ||
        $this->purgedEntries > 0 ||
        $this->prunedAuditRows > 0;
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListLifecycleReport;

#[CoversClass(StatusListLifecycleReport::class)]
class StatusListLifecycleReportTest extends TestCase
{
    public function testCarriesWhatEachStepGotThrough(): void
    {
        $report = new StatusListLifecycleReport(1, 2, 3, 4, 5, ['something went wrong']);

        $this->assertSame(1, $report->getClearedLinkages());
        $this->assertSame(2, $report->getDeactivatedStatusLists());
        $this->assertSame(3, $report->getRetiredStatusLists());
        $this->assertSame(4, $report->getPurgedEntries());
        $this->assertSame(5, $report->getPrunedAuditRows());
        $this->assertSame(['something went wrong'], $report->getFailures());
    }

    /**
     * A cron which had nothing to do should say nothing, rather than adding a line reporting five zeroes
     * to every run of every deployment.
     */
    public function testARunWhichChangedNothingSaysSo(): void
    {
        $this->assertFalse((new StatusListLifecycleReport())->hasChanges());
    }

    public function testAnyStepGettingSomethingDoneCounts(): void
    {
        $this->assertTrue((new StatusListLifecycleReport(0, 0, 0, 0, 1))->hasChanges());
        $this->assertTrue((new StatusListLifecycleReport(1))->hasChanges());
    }

    /**
     * A run which got nothing done because everything failed still has something to report.
     */
    public function testFailuresAreCarriedEvenWhenNothingChanged(): void
    {
        $report = new StatusListLifecycleReport(failures: ['Pruning the status audit trail failed: nope']);

        $this->assertFalse($report->hasChanges());
        $this->assertCount(1, $report->getFailures());
    }
}

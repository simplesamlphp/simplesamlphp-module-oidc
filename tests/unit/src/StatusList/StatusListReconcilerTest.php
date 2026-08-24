<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\StatusListContentHasher;
use SimpleSAML\Module\oidc\StatusList\StatusListReconciler;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListReconciliationCandidate;

#[CoversClass(StatusListReconciler::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusListReconcilerTest extends TestCase
{
    protected MockObject $statusListRepositoryMock;

    protected MockObject $statusListEntryRepositoryMock;

    protected MockObject $loggerServiceMock;

    protected StatusListContentHasher $statusListContentHasher;


    protected function setUp(): void
    {
        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->statusListContentHasher = new StatusListContentHasher();
    }


    protected function sut(): StatusListReconciler
    {
        return new StatusListReconciler(
            $this->statusListRepositoryMock,
            $this->statusListEntryRepositoryMock,
            $this->statusListContentHasher,
            $this->loggerServiceMock,
        );
    }


    protected function record(
        string $id,
        string $signedTokenContentHash,
        int $invalidationCounter = 0,
    ): StatusListReconciliationCandidate {
        return new StatusListReconciliationCandidate($id, 2, 64, $signedTokenContentHash, $invalidationCounter);
    }


    /**
     * @param array<int,int> $statuses
     */
    protected function hashFor(array $statuses): string
    {
        return $this->statusListContentHasher->hash(2, 64, $statuses);
    }


    /**
     * @throws \Exception
     */
    public function testDoesNothingWhenNothingIsPublished(): void
    {
        $this->statusListRepositoryMock->method('findPublished')->willReturn([]);
        $this->statusListRepositoryMock->expects($this->never())->method('invalidatePublishedTokenIfUnchanged');

        $this->assertSame(0, $this->sut()->reconcile());
    }


    /**
     * @throws \Exception
     */
    public function testLeavesATokenWhichStillDescribesItsList(): void
    {
        $this->statusListRepositoryMock->method('findPublished')
            ->willReturn([$this->record('list-a', $this->hashFor([5 => 1]))]);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([5 => 1]);
        $this->statusListRepositoryMock->expects($this->never())->method('invalidatePublishedTokenIfUnchanged');

        $this->assertSame(0, $this->sut()->reconcile());
    }


    /**
     * The failure this exists for: the entry update landed and the invalidation which should have
     * followed it did not, leaving a published token which reports a revoked credential as valid.
     *
     * @throws \Exception
     */
    public function testInvalidatesATokenWhichNoLongerDescribesItsList(): void
    {
        $this->statusListRepositoryMock->method('findPublished')
            ->willReturn([$this->record('list-a', $this->hashFor([]))]);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([5 => 1]);

        $this->statusListRepositoryMock->expects($this->once())->method('invalidatePublishedTokenIfUnchanged')
            ->with('list-a', $this->hashFor([]), 0)
            ->willReturn(true);
        $this->loggerServiceMock->expects($this->once())->method('warning');

        $this->assertSame(1, $this->sut()->reconcile());
    }


    /**
     * A signer may publish a correct token between the batch being read and this decision. Clearing
     * that would be churn, and repeated runs could keep defeating a signer doing the right thing, so
     * the invalidation is conditional and a no-op is not counted or reported as a repair.
     *
     * @throws \Exception
     */
    public function testLeavesATokenPublishedSinceTheBatchWasRead(): void
    {
        $this->statusListRepositoryMock->method('findPublished')
            ->willReturn([$this->record('list-a', $this->hashFor([]))]);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([5 => 1]);

        // The guarded update matched nothing, meaning the token examined is no longer the published one.
        $this->statusListRepositoryMock->method('invalidatePublishedTokenIfUnchanged')->willReturn(false);
        $this->loggerServiceMock->expects($this->never())->method('warning');

        $this->assertSame(0, $this->sut()->reconcile());
    }


    /**
     * A short page means there is no next one, so nothing more is asked for.
     *
     * @throws \Exception
     */
    public function testStopsOnceAPageIsNotFull(): void
    {
        $this->statusListRepositoryMock->expects($this->once())->method('findPublished')
            ->willReturn([$this->record('list-a', $this->hashFor([]))]);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);

        $this->assertSame(0, $this->sut()->reconcile());
    }


    /**
     * Invalidating a list takes it out of the set being paged through, so a numeric offset would step
     * over exactly as many unexamined lists as were invalidated. Resuming after the last identifier
     * seen is unaffected by rows leaving the set behind it.
     *
     * @throws \Exception
     */
    public function testResumesAfterTheLastListItSawRatherThanByCounting(): void
    {
        $full = [];

        for ($position = 0; $position < 100; $position++) {
            // Half are current and half are not, so half the page drops out of the set.
            $statuses = $position % 2 === 0 ? [] : [5 => 1];
            $full[] = $this->record(sprintf('list-%03d', $position), $this->hashFor($statuses));
        }

        $cursors = [];
        $pages = [$full, []];

        $this->statusListRepositoryMock->method('findPublished')->willReturnCallback(
            function (int $limit, ?string $afterId = null) use (&$cursors, &$pages): array {
                $cursors[] = $afterId;

                return array_shift($pages) ?? [];
            },
        );

        // Every list is read as holding one revoked entry, so the ones whose stored hash says otherwise
        // are the fifty which get invalidated.
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([5 => 1]);
        $this->statusListRepositoryMock->method('invalidatePublishedTokenIfUnchanged')->willReturn(true);

        $this->assertSame(50, $this->sut()->reconcile());
        $this->assertSame([null, 'list-099'], $cursors);
    }


    /**
     * Stopping short is not a normal outcome, because every run starts from the beginning: the lists
     * past the ceiling are examined by no run at all. It has to be said out loud rather than passed
     * over.
     *
     * @throws \Exception
     */
    public function testReportsStoppingBeforeTheEnd(): void
    {
        $full = [];

        for ($position = 0; $position < 100; $position++) {
            $full[] = $this->record(sprintf('list-%03d', $position), $this->hashFor([]));
        }

        $this->statusListRepositoryMock->method('findPublished')->willReturn($full);
        $this->statusListEntryRepositoryMock->method('findNonValidStatuses')->willReturn([]);

        $this->loggerServiceMock->expects($this->once())->method('warning')
            ->with($this->stringContains('without reaching the end'));

        $this->assertSame(0, $this->sut()->reconcile());
    }
}

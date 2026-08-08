<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use DateInterval;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusAuditRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\StatusListKeyResolver;
use SimpleSAML\Module\oidc\StatusList\StatusListLifecycle;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPoolBag;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

#[CoversClass(StatusListLifecycle::class)]
class StatusListLifecycleTest extends TestCase
{
    protected const string LIST_ID = 'a-status-list-id';

    protected const string SIGNING_KEY_ID = 'a-signing-key-id';

    protected MockObject $moduleConfigMock;
    protected MockObject $statusListRepositoryMock;
    protected MockObject $statusListEntryRepositoryMock;
    protected MockObject $statusAuditRepositoryMock;
    protected MockObject $statusListKeyResolverMock;
    protected MockObject $loggerServiceMock;
    protected Helpers $helpers;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusAuditRepositoryMock = $this->createMock(StatusAuditRepository::class);
        $this->statusListKeyResolverMock = $this->createMock(StatusListKeyResolver::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->helpers = new Helpers();

        $this->moduleConfigMock->method('getVciStatusListEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getVciStatusListRetirementGrace')->willReturn(new DateInterval('P30D'));
        $this->moduleConfigMock->method('getVciStatusListAuditRetention')->willReturn(null);
        $this->moduleConfigMock->method('getVciStatusListPoolBag')->willReturn(new StatusListPoolBag());
        $this->statusListKeyResolverMock->method('getCurrentKeyId')->willReturn(self::SIGNING_KEY_ID);

        // Nothing to do, unless a test says otherwise.
        $this->statusListEntryRepositoryMock->method('clearExpiredLinkage')->willReturn(0);
        $this->statusListRepositoryMock->method('deactivateSuperseded')->willReturn(0);
        $this->statusListRepositoryMock->method('findRetirementCandidates')->willReturn([]);
        $this->statusListRepositoryMock->method('findRetiredWithEntries')->willReturn([]);
        $this->statusAuditRepositoryMock->method('removeOlderThan')->willReturn(0);
    }

    protected function sut(): StatusListLifecycle
    {
        return new StatusListLifecycle(
            $this->moduleConfigMock,
            $this->statusListRepositoryMock,
            $this->statusListEntryRepositoryMock,
            $this->statusAuditRepositoryMock,
            $this->statusListKeyResolverMock,
            $this->helpers,
            $this->loggerServiceMock,
        );
    }

    /**
     * @throws \Exception
     */
    protected function pool(string $id = 'default'): StatusListPool
    {
        return new StatusListPool(
            $id,
            ['UniversityDegree'],
            1,
            8,
            [StatusTypeEnum::Valid, StatusTypeEnum::Invalid],
            new DateInterval('PT12H'),
            new DateInterval('P7D'),
            new DateInterval('PT1H'),
            StatusListKeyProfileEnum::DidJwk,
        );
    }

    /**
     * @throws \Exception
     */
    public function testKeepsClearingLinkageWhileBatchesComeBackFull(): void
    {
        $batches = [500, 500, 120];

        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('clearExpiredLinkage')
            ->willReturnCallback(static function () use (&$batches): int {
                return (int)(array_shift($batches) ?? 0);
            });

        $this->assertSame(1120, $this->sut()->clearExpiredCredentialLinkage());
    }

    /**
     * @throws \Exception
     */
    public function testStopsClearingLinkageAsSoonAsABatchComesBackShort(): void
    {
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->expects($this->once())
            ->method('clearExpiredLinkage')
            ->willReturn(3);

        $this->assertSame(3, $this->sut()->clearExpiredCredentialLinkage());
    }

    /**
     * @throws \Exception
     */
    public function testDeactivatesListsWhosePolicyIsNoLongerCurrent(): void
    {
        $pool = $this->pool();

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciStatusListEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getVciStatusListPoolBag')->willReturn(new StatusListPoolBag($pool));

        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListRepositoryMock->expects($this->once())
            ->method('deactivateSuperseded')
            ->with(['default' => $pool->getPolicyFingerprint(self::SIGNING_KEY_ID)])
            ->willReturn(2);

        $this->assertSame(2, $this->sut()->deactivateSupersededStatusLists());
    }

    /**
     * An operator who has switched the feature off for a moment has not asked for every list they have
     * to start winding down, and switching it back on would not undo it.
     *
     * @throws \Exception
     */
    public function testDeactivatesNothingWhileStatusListsAreSwitchedOff(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciStatusListEnabled')->willReturn(false);

        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListRepositoryMock->expects($this->never())->method('deactivateSuperseded');

        $this->assertSame(0, $this->sut()->deactivateSupersededStatusLists());
    }

    /**
     * @throws \Exception
     */
    public function testRetiresACandidateAndAsksForItToBeSpentAsOfTheGraceCutOff(): void
    {
        $spentBefore = null;

        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListRepositoryMock->method('findRetirementCandidates')
            ->willReturnOnConsecutiveCalls([self::LIST_ID], []);
        $this->statusListRepositoryMock->expects($this->once())
            ->method('retire')
            ->willReturnCallback(
                static function (string $id, DateTimeImmutable $moment) use (&$spentBefore): bool {
                    $spentBefore = $moment;

                    return $id === self::LIST_ID;
                },
            );

        $this->assertSame(1, $this->sut()->retireSpentStatusLists());
        // A month back, since that is the configured grace, so a credential which lapsed yesterday still
        // holds the list.
        $this->assertInstanceOf(DateTimeImmutable::class, $spentBefore);
        $this->assertLessThan($this->helpers->dateTime()->getUtc(), $spentBefore);
    }

    /**
     * Whether anything is still holding the list is decided by the statement which retires it, not by a
     * read beforehand. A list which stopped qualifying in between -- an issuance which was already in
     * flight, say -- matches no rows, and this must not be counted as a retirement.
     *
     * @throws \Exception
     */
    public function testDoesNotCountAListTheRetiringStatementRefused(): void
    {
        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListRepositoryMock->method('findRetirementCandidates')
            ->willReturnOnConsecutiveCalls([self::LIST_ID], []);
        $this->statusListRepositoryMock->method('retire')->willReturn(false);

        $this->assertSame(0, $this->sut()->retireSpentStatusLists());
    }

    /**
     * Nothing is read from the entries here. Deciding first and retiring second leaves a gap, and there
     * are no transactions to close it with.
     *
     * @throws \Exception
     */
    public function testDoesNotReadTheEntriesBeforeRetiring(): void
    {
        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListRepositoryMock->method('findRetirementCandidates')
            ->willReturnOnConsecutiveCalls([self::LIST_ID], []);
        $this->statusListRepositoryMock->method('retire')->willReturn(true);

        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->expects($this->never())->method('findNonValidStatuses');
        $this->statusListEntryRepositoryMock->expects($this->never())->method('countAllocated');

        $this->assertSame(1, $this->sut()->retireSpentStatusLists());
    }

    /**
     * Retiring a list takes it out of the set being paged through, so the next query has to resume after
     * the last identifier seen rather than at a numeric offset.
     *
     * @throws \Exception
     */
    public function testPagesRetirementCandidatesByCursor(): void
    {
        $seenCursors = [];

        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListRepositoryMock->method('findRetirementCandidates')->willReturnCallback(
            static function (DateTimeImmutable $before, int $limit, ?string $afterId) use (&$seenCursors): array {
                $seenCursors[] = $afterId;

                return $afterId === null ? array_map(
                    static fn(int $position): string => sprintf('list-%03d', $position),
                    range(1, $limit),
                ) : [];
            },
        );
        $this->statusListRepositoryMock->method('retire')->willReturn(false);

        $this->sut()->retireSpentStatusLists();

        $this->assertSame([null, 'list-100'], $seenCursors);
    }

    /**
     * @throws \Exception
     */
    public function testRemovesTheEntriesOfRetiredListsUntilNoneAreLeft(): void
    {
        $batches = [1000, 1000, 250];

        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListRepositoryMock->method('findRetiredWithEntries')->willReturn([self::LIST_ID]);

        $this->statusListEntryRepositoryMock->method('deleteRetiredEntries')
            ->willReturnCallback(static function () use (&$batches): int {
                return (int)(array_shift($batches) ?? 0);
            });

        $this->assertSame(2250, $this->sut()->purgeRetiredStatusListEntries());
    }

    /**
     * @throws \Exception
     */
    public function testRemovesNoEntriesWhenNoListHasBeenRetired(): void
    {
        $this->statusListEntryRepositoryMock->expects($this->never())->method('deleteRetiredEntries');

        $this->assertSame(0, $this->sut()->purgeRetiredStatusListEntries());
    }

    /**
     * A list retired a moment ago is left alone. Retirement can not be serialised against an issuance
     * which was already in flight, so a credential can land in a list just after it was retired --
     * unverifiable, but at least still on record until these rows go too.
     *
     * @throws \Exception
     */
    public function testAsksOnlyForListsRetiredLongerAgoThanTheGracePeriod(): void
    {
        $retiredBefore = null;

        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListRepositoryMock->method('findRetiredWithEntries')->willReturnCallback(
            static function (int $limit, DateTimeImmutable $moment) use (&$retiredBefore): array {
                $retiredBefore = $moment;

                return [];
            },
        );

        $this->sut()->purgeRetiredStatusListEntries();

        $this->assertInstanceOf(DateTimeImmutable::class, $retiredBefore);
        // A month back, since that is the configured grace.
        $this->assertLessThan($this->helpers->dateTime()->getUtc(), $retiredBefore);
    }

    /**
     * How long a record of who revoked what needs keeping follows from the deployment's own obligations,
     * so nothing is discarded unless an operator has said how long is long enough.
     *
     * @throws \Exception
     */
    public function testPrunesNoAuditRowsWithoutAConfiguredRetention(): void
    {
        $this->statusAuditRepositoryMock = $this->createMock(StatusAuditRepository::class);
        $this->statusAuditRepositoryMock->expects($this->never())->method('removeOlderThan');

        $this->assertSame(0, $this->sut()->pruneStatusAuditTrail());
    }

    /**
     * @throws \Exception
     */
    public function testPrunesAuditRowsOlderThanTheRetention(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciStatusListAuditRetention')->willReturn(new DateInterval('P1Y'));

        $cutOff = null;

        $this->statusAuditRepositoryMock = $this->createMock(StatusAuditRepository::class);
        $this->statusAuditRepositoryMock->method('removeOlderThan')->willReturnCallback(
            static function (DateTimeImmutable $createdBefore) use (&$cutOff): int {
                $cutOff = $createdBefore;

                return 7;
            },
        );

        $this->assertSame(7, $this->sut()->pruneStatusAuditTrail());
        $this->assertInstanceOf(DateTimeImmutable::class, $cutOff);
        $this->assertLessThan($this->helpers->dateTime()->getUtc(), $cutOff);
    }

    /**
     * @throws \Exception
     */
    public function testRunReportsWhatEachStepGotThrough(): void
    {
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('clearExpiredLinkage')->willReturn(4);
        $this->statusListEntryRepositoryMock->method('deleteRetiredEntries')
            ->willReturnOnConsecutiveCalls(6, 0);

        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListRepositoryMock->method('deactivateSuperseded')->willReturn(2);
        $this->statusListRepositoryMock->method('findRetirementCandidates')
            ->willReturnOnConsecutiveCalls([self::LIST_ID], []);
        $this->statusListRepositoryMock->method('retire')->willReturn(true);
        $this->statusListRepositoryMock->method('findRetiredWithEntries')->willReturn([self::LIST_ID]);

        $report = $this->sut()->run();

        $this->assertSame(4, $report->getClearedLinkages());
        $this->assertSame(2, $report->getDeactivatedStatusLists());
        $this->assertSame(1, $report->getRetiredStatusLists());
        $this->assertSame(6, $report->getPurgedEntries());
        $this->assertSame(0, $report->getPrunedAuditRows());
        $this->assertSame([], $report->getFailures());
        $this->assertTrue($report->hasChanges());
    }

    /**
     * The steps share tables but not purposes, and one of them is an undertaking made to the people the
     * credentials were issued to. A failure elsewhere must not quietly suspend it.
     *
     * @throws \Exception
     */
    public function testRunCarriesOnAfterAStepFails(): void
    {
        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->statusListRepositoryMock->method('deactivateSuperseded')
            ->willThrowException(new RuntimeException('the database went away'));
        $this->statusListRepositoryMock->method('findRetirementCandidates')->willReturn([]);
        $this->statusListRepositoryMock->method('findRetiredWithEntries')->willReturn([]);

        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->expects($this->once())
            ->method('clearExpiredLinkage')
            ->willReturn(9);

        $report = $this->sut()->run();

        $this->assertSame(9, $report->getClearedLinkages());
        $this->assertSame(0, $report->getDeactivatedStatusLists());
        $this->assertCount(1, $report->getFailures());
        $this->assertStringContainsString('the database went away', $report->getFailures()[0]);
    }

    /**
     * @throws \Exception
     */
    public function testRunOfADeploymentWithNothingToDoReportsNoChanges(): void
    {
        $this->assertFalse($this->sut()->run()->hasChanges());
    }
}

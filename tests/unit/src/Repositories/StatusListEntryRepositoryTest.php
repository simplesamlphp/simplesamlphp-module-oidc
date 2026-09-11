<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateTimeImmutable;
use PDO;
use PDOStatement;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

#[CoversClass(StatusListEntryRepository::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusListEntryRepositoryTest extends TestCase
{
    protected const string LIST_ID = 'a-status-list-id';

    protected const string OTHER_LIST_ID = 'another-status-list-id';

    protected const string CONFIGURATION_ID = 'UniversityDegree';

    protected const int CAPACITY = 8;

    /**
     * What a statement may bind before the oldest supported driver refuses it.
     *
     * Stated here rather than read from the repository, so that the tests assert the limit the drivers
     * impose and not merely that the code agrees with itself.
     */
    protected const int MAX_BOUND_VARIABLES = 999;


    protected MockObject $moduleConfigMock;

    protected Helpers $helpers;

    protected StatusListEntryRepository $repository;

    protected StatusListRepository $statusListRepository;

    protected int $itemsPerPage = 20;


    /**
     * @throws \Exception
     */
    public static function setUpBeforeClass(): void
    {
        Configuration::loadFromArray(
            [
                'database.dsn' => 'sqlite::memory:',
                'database.username' => null,
                'database.password' => null,
                'database.prefix' => 'phpunit_',
                'database.persistent' => true,
                'database.secondaries' => [],
            ],
            '',
            'simplesaml',
        );

        (new DatabaseMigration())->migrate();
    }


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        // Resolved at call time rather than at stub time, so a test can change the page size after the
        // mock has been set up.
        $this->moduleConfigMock->method('config')->willReturnCallback(
            fn(): Configuration => Configuration::loadFromArray(
                [ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE => $this->itemsPerPage],
            ),
        );
        $this->itemsPerPage = 20;
        $this->helpers = new Helpers();

        $this->repository = new StatusListEntryRepository(
            $this->moduleConfigMock,
            Database::getInstance(),
            null,
            $this->helpers,
        );

        $this->statusListRepository = new StatusListRepository(
            $this->moduleConfigMock,
            Database::getInstance(),
            null,
            $this->helpers,
        );

        Database::getInstance()->write(sprintf('DELETE FROM %s', $this->repository->getTableName()));
        Database::getInstance()->write(sprintf('DELETE FROM %s', $this->statusListRepository->getTableName()));
    }


    protected function setItemsPerPage(int $itemsPerPage): void
    {
        $this->itemsPerPage = $itemsPerPage;
    }


    /**
     * The lane defaults to the non-expiring one because allocate() below defaults to no expiry, and
     * allocation is refused when the two disagree. A test which gives its credentials an expiry has to
     * say so here too, which is the invariant working as intended rather than an inconvenience.
     *
     * @throws \Exception
     */
    protected function createList(
        string $id = self::LIST_ID,
        int $generation = 1,
        StatusListExpiryLaneEnum $expiryLane = StatusListExpiryLaneEnum::NonExpiring,
    ): void {
        $this->statusListRepository->create(
            $id,
            'https://op.example.org/statuslist/' . $id,
            'default',
            'a-policy-fingerprint',
            $expiryLane,
            $generation,
            1,
            self::CAPACITY,
            implode(',', [StatusTypeEnum::Valid->value, StatusTypeEnum::Invalid->value]),
            43200,
            604800,
            3600,
            'a-signing-key-id',
            StatusListKeyProfileEnum::DidJwk,
        );

        $this->repository->seed($id, self::CAPACITY);
        // Allocation only claims an index while the list accepts them, and a list is created closed.
        $this->statusListRepository->activate($id);
    }


    /**
     * @throws \Exception
     */
    protected function allocate(
        int $idx,
        string $credentialId,
        ?string $subjectRef = null,
        ?DateTimeImmutable $issuedAt = null,
        ?DateTimeImmutable $expiresAt = null,
        string $statusListId = self::LIST_ID,
    ): void {
        $this->repository->allocate(
            $statusListId,
            $idx,
            $credentialId,
            $this->repository->hashCredentialId($credentialId),
            self::CONFIGURATION_ID,
            $subjectRef,
            $expiresAt,
            $issuedAt ?? new DateTimeImmutable('2026-08-07 12:00:00'),
        );
    }


    /**
     * @throws \Exception
     */
    protected function updateStatus(
        int $idx,
        StatusTypeEnum $observed,
        StatusTypeEnum $new,
        string $statusListId = self::LIST_ID,
    ): bool {
        return $this->repository->updateStatus($statusListId, $idx, $observed->value, $new->value);
    }


    /**
     * @param \SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord[] $entries
     * @return string[]
     */
    protected function credentialIdsOf(array $entries): array
    {
        return array_map(
            static fn(StatusListEntryRecord $entry): string => (string)$entry->getCredentialId(),
            $entries,
        );
    }


    /**
     * Every index exists as a row from the moment a list is created, so a listing which did not filter
     * on allocation would show tens of thousands of things nobody was ever issued.
     *
     * @throws \Exception
     */
    public function testListsOnlyAllocatedEntries(): void
    {
        $this->createList();
        $this->allocate(0, 'urn:vc:one');

        $page = $this->repository->findAllocatedPaginated();

        $this->assertSame(1, $page['total']);
        $this->assertSame(['urn:vc:one'], $this->credentialIdsOf($page['items']));
    }


    /**
     * @throws \Exception
     */
    public function testListsNewestFirst(): void
    {
        $this->createList();
        $this->allocate(0, 'urn:vc:older', null, new DateTimeImmutable('2026-08-01 09:00:00'));
        $this->allocate(1, 'urn:vc:newer', null, new DateTimeImmutable('2026-08-06 09:00:00'));

        $this->assertSame(
            ['urn:vc:newer', 'urn:vc:older'],
            $this->credentialIdsOf($this->repository->findAllocatedPaginated()['items']),
        );
    }


    /**
     * A batch issuance stamps the same moment on every credential in it. An order which left those
     * rows free to come back in any sequence would show one of them twice and another not at all as an
     * administrator pages through.
     *
     * @throws \Exception
     */
    public function testPagesThroughEntriesIssuedAtTheSameMomentWithoutRepeatingOrLosingAny(): void
    {
        $this->setItemsPerPage(2);
        $this->createList();

        $issuedAt = new DateTimeImmutable('2026-08-07 12:00:00');

        for ($idx = 0; $idx < 5; $idx++) {
            $this->allocate($idx, 'urn:vc:' . $idx, null, $issuedAt);
        }

        $seen = array_merge(
            $this->credentialIdsOf($this->repository->findAllocatedPaginated(1)['items']),
            $this->credentialIdsOf($this->repository->findAllocatedPaginated(2)['items']),
            $this->credentialIdsOf($this->repository->findAllocatedPaginated(3)['items']),
        );

        sort($seen);

        $this->assertSame(['urn:vc:0', 'urn:vc:1', 'urn:vc:2', 'urn:vc:3', 'urn:vc:4'], $seen);
    }


    /**
     * @throws \Exception
     */
    public function testReportsThePageCount(): void
    {
        $this->setItemsPerPage(2);
        $this->createList();

        for ($idx = 0; $idx < 5; $idx++) {
            $this->allocate($idx, 'urn:vc:' . $idx);
        }

        $page = $this->repository->findAllocatedPaginated();

        $this->assertSame(5, $page['total']);
        $this->assertSame(3, $page['numPages']);
        $this->assertSame(1, $page['currentPage']);
        $this->assertCount(2, $page['items']);
    }


    /**
     * A page number out of range is a bookmark or a typo, not something to answer with an empty table.
     *
     * @throws \Exception
     */
    public function testClampsThePageToWhatExists(): void
    {
        $this->setItemsPerPage(2);
        $this->createList();
        $this->allocate(0, 'urn:vc:one');

        $this->assertSame(1, $this->repository->findAllocatedPaginated(99)['currentPage']);
        $this->assertSame(1, $this->repository->findAllocatedPaginated(-5)['currentPage']);
    }


    /**
     * @throws \Exception
     */
    public function testFindsByCredentialIdentifier(): void
    {
        $this->createList();
        $this->allocate(0, 'urn:vc:one');
        $this->allocate(1, 'urn:vc:two');

        $page = $this->repository->findAllocatedPaginated(
            1,
            $this->repository->hashCredentialId('urn:vc:two'),
            null,
        );

        $this->assertSame(1, $page['total']);
        $this->assertSame(['urn:vc:two'], $this->credentialIdsOf($page['items']));
    }


    /**
     * Every credential issued to one person, which is what a lost device or a leaver comes down to.
     *
     * @throws \Exception
     */
    public function testFindsEveryCredentialOfOneSubject(): void
    {
        $this->createList();
        $this->allocate(0, 'urn:vc:one', 'a-subject-ref');
        $this->allocate(1, 'urn:vc:two', 'a-subject-ref');
        $this->allocate(2, 'urn:vc:three', 'another-subject-ref');

        $page = $this->repository->findAllocatedPaginated(1, null, 'a-subject-ref');

        $found = $this->credentialIdsOf($page['items']);
        sort($found);

        $this->assertSame(2, $page['total']);
        $this->assertSame(['urn:vc:one', 'urn:vc:two'], $found);
    }


    /**
     * One box, both stored forms of what was typed, either matching being a hit.
     *
     * @throws \Exception
     */
    public function testMatchesEitherStoredFormOfTheSearchTerm(): void
    {
        $this->createList();
        $this->allocate(0, 'urn:vc:one', 'a-subject-ref');

        $this->assertSame(
            1,
            $this->repository->findAllocatedPaginated(
                1,
                $this->repository->hashCredentialId('urn:vc:one'),
                'no-such-subject-ref',
            )['total'],
        );

        $this->assertSame(
            1,
            $this->repository->findAllocatedPaginated(
                1,
                $this->repository->hashCredentialId('urn:vc:nothing'),
                'a-subject-ref',
            )['total'],
        );
    }


    /**
     * @throws \Exception
     */
    public function testFindsNothingWhenNeitherFormMatches(): void
    {
        $this->createList();
        $this->allocate(0, 'urn:vc:one', 'a-subject-ref');

        $page = $this->repository->findAllocatedPaginated(
            1,
            $this->repository->hashCredentialId('urn:vc:nothing'),
            'no-such-subject-ref',
        );

        $this->assertSame(0, $page['total']);
        $this->assertSame([], $page['items']);
    }


    /**
     * An unallocated row has no expiry either, and counting those would report every list a deployment
     * has as permanent from the moment it was created.
     *
     * @throws \Exception
     */
    public function testCountsOnlyListsHoldingAnAllocatedCredentialWhichNeverExpires(): void
    {
        // One list per lane, because that is now the only way the two kinds coexist: a credential with
        // an expiry cannot be allocated into the non-expiring list, nor one without into the other.
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::Expiring);
        $this->createList(self::OTHER_LIST_ID, 2, StatusListExpiryLaneEnum::NonExpiring);

        $this->assertSame(0, $this->repository->countNeverRetiringLists());

        $this->allocate(0, 'urn:vc:expiring', null, null, new DateTimeImmutable('2027-08-07 12:00:00'));

        $this->assertSame(0, $this->repository->countNeverRetiringLists());

        $this->allocate(1, 'urn:vc:permanent', null, null, null, self::OTHER_LIST_ID);

        $this->assertSame(1, $this->repository->countNeverRetiringLists());
    }


    /**
     * @throws \Exception
     */
    public function testCountsEachListOnceHoweverManyPermanentCredentialsItHolds(): void
    {
        $this->createList();
        $this->createList(self::OTHER_LIST_ID, 2);

        $this->allocate(0, 'urn:vc:one');
        $this->allocate(1, 'urn:vc:two');
        $this->allocate(0, 'urn:vc:three', null, null, null, self::OTHER_LIST_ID);

        $this->assertSame(2, $this->repository->countNeverRetiringLists());
    }


    /**
     * @return array<string,mixed>
     */
    protected function readEntry(int $idx, string $statusListId = self::LIST_ID): array
    {
        $rows = Database::getInstance()->readPrimary(
            sprintf(
                'SELECT * FROM %s WHERE status_list_id = :status_list_id AND idx = :idx',
                $this->repository->getTableName(),
            ),
            [
                'status_list_id' => $statusListId,
                'idx' => $idx,
            ],
        )->fetchAll();

        $this->assertIsArray($rows[0] ?? null);

        return $rows[0];
    }


    /**
     * The four linkage columns are one fact, so they go together. Keeping any of them would leave a row
     * which still says somebody was issued a credential while claiming not to know which one.
     *
     * @throws \Exception
     */
    public function testClearsTheWholeLinkageOfAnExpiredCredential(): void
    {
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::Expiring);
        $this->allocate(
            0,
            'urn:vc:expired',
            'a-subject-ref',
            new DateTimeImmutable('2026-01-01 09:00:00'),
            new DateTimeImmutable('2026-06-01 09:00:00'),
        );

        $this->assertSame(1, $this->repository->clearExpiredLinkage(new DateTimeImmutable('2026-08-07 12:00:00'), 10));

        $entry = $this->readEntry(0);

        $this->assertNull($entry['credential_id']);
        $this->assertNull($entry['credential_id_hash']);
        $this->assertNull($entry['credential_configuration_id']);
        $this->assertNull($entry['subject_ref']);
    }


    /**
     * What is kept is what the published token is built from, and what stops the index being handed out
     * to a second credential.
     *
     * @throws \Exception
     */
    public function testKeepsTheIndexItsStatusAndItsExpiryWhenClearingLinkage(): void
    {
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::Expiring);
        $this->allocate(
            3,
            'urn:vc:expired',
            null,
            new DateTimeImmutable('2026-01-01 09:00:00'),
            new DateTimeImmutable('2026-06-01 09:00:00'),
        );
        $this->repository->updateStatus(self::LIST_ID, 3, StatusTypeEnum::Valid->value, StatusTypeEnum::Invalid->value);

        $this->repository->clearExpiredLinkage(new DateTimeImmutable('2026-08-07 12:00:00'), 10);

        $entry = $this->readEntry(3);

        $this->assertSame(3, (int)$entry['idx']);
        $this->assertSame(StatusTypeEnum::Invalid->value, (int)$entry['status']);
        $this->assertNotNull($entry['expires_at']);
        // Still allocated, so the index can never be claimed again.
        $this->assertNotEmpty($entry['allocated']);
    }


    /**
     * @throws \Exception
     */
    public function testLeavesCredentialsWhichHaveNotExpiredAlone(): void
    {
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::Expiring);
        $this->allocate(
            0,
            'urn:vc:live',
            null,
            new DateTimeImmutable('2026-01-01 09:00:00'),
            new DateTimeImmutable('2027-06-01 09:00:00'),
        );

        $this->assertSame(0, $this->repository->clearExpiredLinkage(new DateTimeImmutable('2026-08-07 12:00:00'), 10));
        $this->assertSame('urn:vc:live', $this->readEntry(0)['credential_id']);
    }


    /**
     * The guard which makes the expiry lane an invariant rather than a convention. The lane it compares
     * against is derived inside allocate() from the expiry being written, so a caller cannot arrange for
     * the two to disagree, and a list simply refuses the wrong kind of credential.
     *
     * @throws \Exception
     */
    public function testRefusesToAllocateACredentialWithNoExpiryIntoAnExpiringList(): void
    {
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::Expiring);

        $this->assertFalse(
            $this->repository->allocate(
                self::LIST_ID,
                0,
                'urn:vc:permanent',
                $this->repository->hashCredentialId('urn:vc:permanent'),
                self::CONFIGURATION_ID,
                null,
                null,
            ),
        );

        // Refused, not merely reported as refused: the index has to still be free, or the allocator's
        // response of probing elsewhere would leak an index on every attempt.
        $this->assertEmpty($this->readEntry(0)['allocated']);
        $this->assertNull($this->readEntry(0)['credential_id']);
    }


    /**
     * The other direction, which harms nothing on its own -- a non-expiring list is never retired
     * whatever it holds -- but is the same defect seen from the other side, and is what the mismatch
     * monitor's second half looks for.
     *
     * @throws \Exception
     */
    public function testRefusesToAllocateAnExpiringCredentialIntoANonExpiringList(): void
    {
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::NonExpiring);

        $this->assertFalse(
            $this->repository->allocate(
                self::LIST_ID,
                0,
                'urn:vc:expiring',
                $this->repository->hashCredentialId('urn:vc:expiring'),
                self::CONFIGURATION_ID,
                null,
                new DateTimeImmutable('2027-08-07 12:00:00'),
            ),
        );

        $this->assertEmpty($this->readEntry(0)['allocated']);
    }


    /**
     * @throws \Exception
     */
    public function testCountsNoLaneMismatchesWhenEveryListHoldsWhatItsLaneSays(): void
    {
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::Expiring);
        $this->createList(self::OTHER_LIST_ID, 2, StatusListExpiryLaneEnum::NonExpiring);

        $this->allocate(0, 'urn:vc:expiring', null, null, new DateTimeImmutable('2027-08-07 12:00:00'));
        $this->allocate(0, 'urn:vc:permanent', null, null, null, self::OTHER_LIST_ID);

        $this->assertSame(0, $this->repository->countLaneMismatches());
    }


    /**
     * Written past the guard on purpose, since nothing in the module can produce this state any more.
     * The monitor exists for the case where something did anyway -- a hand-edited row, a restore from
     * older data, a future code path which forgot -- so the test has to manufacture what it detects.
     *
     * @throws \Exception
     */
    public function testCountsALaneMismatchInEitherDirection(): void
    {
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::Expiring);
        $this->createList(self::OTHER_LIST_ID, 2, StatusListExpiryLaneEnum::NonExpiring);

        // An expiring list holding a credential which never expires: the harmful direction, since this
        // list can now never be retired.
        $this->allocate(0, 'urn:vc:expiring', null, null, new DateTimeImmutable('2027-08-07 12:00:00'));
        $this->forceExpiry(self::LIST_ID, 0, null);

        $this->assertSame(1, $this->repository->countLaneMismatches());

        // A non-expiring list holding one which does expire: harmless, but still a mismatch.
        $this->allocate(0, 'urn:vc:permanent', null, null, null, self::OTHER_LIST_ID);
        $this->forceExpiry(self::OTHER_LIST_ID, 0, '2027-08-07 12:00:00');

        $this->assertSame(2, $this->repository->countLaneMismatches());
    }


    /**
     * Sets an entry's expiry directly, bypassing the lane guard in allocate(), so that a state the
     * module refuses to create can be put in front of the monitor which looks for it.
     *
     * @throws \Exception
     */
    protected function forceExpiry(string $statusListId, int $idx, ?string $expiresAt): void
    {
        Database::getInstance()->write(
            sprintf(
                'UPDATE %s SET expires_at = :expires_at WHERE status_list_id = :status_list_id AND idx = :idx',
                $this->repository->getTableName(),
            ),
            [
                'expires_at' => $expiresAt,
                'status_list_id' => $statusListId,
                'idx' => $idx,
            ],
        );
    }


    /**
     * A credential without an expiry is one which can be presented at any point in the future, so the
     * linkage which makes it revocable has to outlive every cut-off.
     *
     * @throws \Exception
     */
    public function testNeverClearsTheLinkageOfACredentialWithoutAnExpiry(): void
    {
        $this->createList();
        $this->allocate(0, 'urn:vc:permanent');

        $this->assertSame(0, $this->repository->clearExpiredLinkage(new DateTimeImmutable('2099-01-01 00:00:00'), 10));
        $this->assertSame('urn:vc:permanent', $this->readEntry(0)['credential_id']);
    }


    /**
     * @throws \Exception
     */
    public function testClearsNoMoreThanTheGivenNumberOfLinkages(): void
    {
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::Expiring);

        for ($idx = 0; $idx < 5; $idx++) {
            $this->allocate(
                $idx,
                'urn:vc:' . $idx,
                null,
                new DateTimeImmutable('2026-01-01 09:00:00'),
                new DateTimeImmutable('2026-06-01 09:00:00'),
            );
        }

        $now = new DateTimeImmutable('2026-08-07 12:00:00');

        $this->assertSame(2, $this->repository->clearExpiredLinkage($now, 2));
        $this->assertSame(2, $this->repository->clearExpiredLinkage($now, 2));
        $this->assertSame(1, $this->repository->clearExpiredLinkage($now, 2));
        $this->assertSame(0, $this->repository->clearExpiredLinkage($now, 2));
    }


    /**
     * An allocated row whose credential has expired names no credential any more, so there is nothing an
     * administrator could ask about it or do to it.
     *
     * @throws \Exception
     */
    public function testStopsListingEntriesWhoseLinkageHasBeenCleared(): void
    {
        $this->createList();
        $this->allocate(
            0,
            'urn:vc:expired',
            null,
            new DateTimeImmutable('2026-01-01 09:00:00'),
            new DateTimeImmutable('2026-06-01 09:00:00'),
        );
        $this->allocate(1, 'urn:vc:live', null, new DateTimeImmutable('2026-01-02 09:00:00'));

        $this->repository->clearExpiredLinkage(new DateTimeImmutable('2026-08-07 12:00:00'), 10);

        $page = $this->repository->findAllocatedPaginated();

        $this->assertSame(1, $page['total']);
        $this->assertSame(['urn:vc:live'], $this->credentialIdsOf($page['items']));
    }


    protected function countEntriesOf(string $statusListId): int
    {
        $rows = Database::getInstance()->readPrimary(
            sprintf(
                'SELECT COUNT(*) AS entry_total FROM %s WHERE status_list_id = :status_list_id',
                $this->repository->getTableName(),
            ),
            ['status_list_id' => $statusListId],
        )->fetchAll();

        return (int)$rows[0]['entry_total'];
    }


    /**
     * @throws \Exception
     */
    public function testRemovesRetiredEntriesInBoundedRuns(): void
    {
        $this->createList();

        $this->assertSame(3, $this->repository->deleteRetiredEntries(self::LIST_ID, 3));
        $this->assertSame(self::CAPACITY - 3, $this->countEntriesOf(self::LIST_ID));

        $this->assertSame(3, $this->repository->deleteRetiredEntries(self::LIST_ID, 3));
        $this->assertSame(2, $this->repository->deleteRetiredEntries(self::LIST_ID, 3));
        $this->assertSame(0, $this->repository->deleteRetiredEntries(self::LIST_ID, 3));
        $this->assertSame(0, $this->countEntriesOf(self::LIST_ID));
    }


    /**
     * @throws \Exception
     */
    public function testRemovesEntriesOfOneListOnly(): void
    {
        $this->createList();
        $this->createList(self::OTHER_LIST_ID, 2);

        $this->repository->deleteRetiredEntries(self::LIST_ID, self::CAPACITY);

        $this->assertSame(0, $this->countEntriesOf(self::LIST_ID));
        $this->assertSame(self::CAPACITY, $this->countEntriesOf(self::OTHER_LIST_ID));
    }


    /**
     * The lookup every status change begins with: `CredentialStatusService` is handed a credential
     * identifier, hashes it, and asks for the entry -- and the entry has to carry everything the service
     * then acts on, including the expiry which decides whether it still can.
     *
     * @throws \Exception
     */
    public function testFindsAnAllocatedEntryByTheHashOfItsCredentialIdentifier(): void
    {
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::Expiring);
        $issuedAt = new DateTimeImmutable('2026-01-01 09:00:00');
        $expiresAt = new DateTimeImmutable('2027-06-01 09:00:00');
        $this->allocate(5, 'urn:vc:one', 'a-subject-ref', $issuedAt, $expiresAt);
        $this->allocate(6, 'urn:vc:two', 'another-subject-ref', $issuedAt, $expiresAt);

        $entry = $this->repository->findByCredentialIdHash($this->repository->hashCredentialId('urn:vc:one'));

        $this->assertInstanceOf(StatusListEntryRecord::class, $entry);
        $this->assertSame(self::LIST_ID, $entry->getStatusListId());
        $this->assertSame(5, $entry->getIdx());
        $this->assertTrue($entry->isAllocated());
        $this->assertSame(StatusTypeEnum::Valid->value, $entry->getStatus());
        $this->assertSame('urn:vc:one', $entry->getCredentialId());
        $this->assertSame($this->repository->hashCredentialId('urn:vc:one'), $entry->getCredentialIdHash());
        $this->assertSame(self::CONFIGURATION_ID, $entry->getCredentialConfigurationId());
        $this->assertSame('a-subject-ref', $entry->getSubjectRef());
        $this->assertSame($issuedAt->getTimestamp(), $entry->getIssuedAt()?->getTimestamp());
        $this->assertSame($expiresAt->getTimestamp(), $entry->getExpiresAt()?->getTimestamp());
    }


    /**
     * The column carrying the identifier itself is unindexed text which nothing looks up by, so the
     * identifier finds nothing where its hash finds the entry. A caller which forgot to hash gets a
     * miss, not a slow hit.
     *
     * @throws \Exception
     */
    public function testFindsNothingByAHashWhichNoEntryCarries(): void
    {
        $this->createList();
        $this->allocate(0, 'urn:vc:one');

        $this->assertNull($this->repository->findByCredentialIdHash('urn:vc:one'));
        $this->assertNull($this->repository->findByCredentialIdHash($this->repository->hashCredentialId('urn:vc:two')));
    }


    /**
     * Once the linkage is cleared there is no hash left to find the entry by, and that is the bargain:
     * the record of who was issued what lasts exactly as long as the credential can be presented. The
     * entry itself is still there under its list and index, still allocated, and still carries the
     * status it ended on -- which the published list goes on reporting.
     *
     * @throws \Exception
     */
    public function testNoLongerFindsAnEntryByHashOnceItsLinkageHasBeenCleared(): void
    {
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::Expiring);
        $this->allocate(
            2,
            'urn:vc:expired',
            'a-subject-ref',
            new DateTimeImmutable('2026-01-01 09:00:00'),
            new DateTimeImmutable('2026-06-01 09:00:00'),
        );
        $this->updateStatus(2, StatusTypeEnum::Valid, StatusTypeEnum::Invalid);
        $this->repository->clearExpiredLinkage(new DateTimeImmutable('2026-08-07 12:00:00'), 10);

        $this->assertNull(
            $this->repository->findByCredentialIdHash($this->repository->hashCredentialId('urn:vc:expired')),
        );

        $entry = $this->repository->findByListAndIdx(self::LIST_ID, 2);

        $this->assertInstanceOf(StatusListEntryRecord::class, $entry);
        $this->assertTrue($entry->isAllocated());
        $this->assertSame(StatusTypeEnum::Invalid->value, $entry->getStatus());
        $this->assertNull($entry->getCredentialId());
        $this->assertNull($entry->getCredentialIdHash());
        $this->assertNull($entry->getCredentialConfigurationId());
        $this->assertNull($entry->getSubjectRef());
        $this->assertSame(
            [2 => StatusTypeEnum::Invalid->value],
            $this->repository->findNonValidStatuses(self::LIST_ID),
        );
    }


    /**
     * The index is only unique within its list, so the same index in another list is another entry.
     *
     * @throws \Exception
     */
    public function testFindsAnEntryByItsListAndIndex(): void
    {
        $this->createList();
        $this->createList(self::OTHER_LIST_ID, 2);
        $this->allocate(3, 'urn:vc:one', 'a-subject-ref');
        $this->allocate(3, 'urn:vc:other', null, null, null, self::OTHER_LIST_ID);

        $entry = $this->repository->findByListAndIdx(self::LIST_ID, 3);

        $this->assertInstanceOf(StatusListEntryRecord::class, $entry);
        $this->assertSame(self::LIST_ID, $entry->getStatusListId());
        $this->assertSame(3, $entry->getIdx());
        $this->assertTrue($entry->isAllocated());
        $this->assertSame('urn:vc:one', $entry->getCredentialId());
        $this->assertSame(self::CONFIGURATION_ID, $entry->getCredentialConfigurationId());
        $this->assertSame('a-subject-ref', $entry->getSubjectRef());
        $this->assertTrue($entry->isNonExpiring());

        $this->assertSame(
            'urn:vc:other',
            $this->repository->findByListAndIdx(self::OTHER_LIST_ID, 3)?->getCredentialId(),
        );
    }


    /**
     * Every index exists as a row from the moment the list is created, so an index nothing was issued
     * at is found, and found unallocated. An index the list does not have at all is not found, and
     * `DbStatusUpdater::requireAllocatedEntry()` reports the two differently.
     *
     * @throws \Exception
     */
    public function testFindsANeverAllocatedIndexAsAnUnallocatedEntry(): void
    {
        $this->createList();

        $entry = $this->repository->findByListAndIdx(self::LIST_ID, self::CAPACITY - 1);

        $this->assertInstanceOf(StatusListEntryRecord::class, $entry);
        $this->assertSame(self::CAPACITY - 1, $entry->getIdx());
        $this->assertFalse($entry->isAllocated());
        $this->assertSame(StatusTypeEnum::Valid->value, $entry->getStatus());
        $this->assertNull($entry->getCredentialId());
        $this->assertNull($entry->getCredentialIdHash());
        $this->assertNull($entry->getCredentialConfigurationId());
        $this->assertNull($entry->getSubjectRef());
        $this->assertNull($entry->getIssuedAt());
        $this->assertNull($entry->getUpdatedAt());
        $this->assertTrue($entry->isNonExpiring());

        $this->assertNull($this->repository->findByListAndIdx(self::LIST_ID, self::CAPACITY));
        $this->assertNull($this->repository->findByListAndIdx('no-such-list', 0));
    }


    /**
     * Conditioned on the status the caller observed. The second of two changes racing each other finds
     * the status is no longer what it read and gets false back, rather than overwriting the first; a
     * caller which observed what is there now gets through.
     *
     * @throws \Exception
     */
    public function testChangesAStatusOnlyFromTheStatusTheCallerObserved(): void
    {
        $this->createList();
        $this->allocate(0, 'urn:vc:one');

        $this->assertTrue($this->updateStatus(0, StatusTypeEnum::Valid, StatusTypeEnum::Invalid));
        $this->assertSame(StatusTypeEnum::Invalid->value, (int)$this->readEntry(0)['status']);

        $this->assertFalse($this->updateStatus(0, StatusTypeEnum::Valid, StatusTypeEnum::Suspended));
        $this->assertSame(StatusTypeEnum::Invalid->value, (int)$this->readEntry(0)['status']);

        $this->assertTrue($this->updateStatus(0, StatusTypeEnum::Invalid, StatusTypeEnum::Suspended));
        $this->assertSame(StatusTypeEnum::Suspended->value, (int)$this->readEntry(0)['status']);
    }


    /**
     * An index nothing was issued at has a status too -- Valid, from the seed -- and it has to stay out
     * of reach: a status written there would be published for a credential which does not exist.
     *
     * @throws \Exception
     */
    public function testRefusesToChangeTheStatusOfAnUnallocatedIndex(): void
    {
        $this->createList();

        $this->assertFalse($this->updateStatus(0, StatusTypeEnum::Valid, StatusTypeEnum::Invalid));
        $this->assertSame(StatusTypeEnum::Valid->value, (int)$this->readEntry(0)['status']);
    }


    /**
     * @throws \Exception
     */
    public function testStampsTheMomentOfAStatusChange(): void
    {
        $this->createList();
        $this->allocate(0, 'urn:vc:one', null, new DateTimeImmutable('2026-01-01 09:00:00'));

        $before = $this->helpers->dateTime()->getUtc()->getTimestamp();
        $this->updateStatus(0, StatusTypeEnum::Valid, StatusTypeEnum::Invalid);
        $after = $this->helpers->dateTime()->getUtc()->getTimestamp();

        $updatedAt = $this->repository->findByListAndIdx(self::LIST_ID, 0)?->getUpdatedAt()?->getTimestamp();

        $this->assertGreaterThanOrEqual($before, $updatedAt);
        $this->assertLessThanOrEqual($after, $updatedAt);
    }


    /**
     * What a published list is rebuilt from. Every index the answer leaves out is Valid, which includes
     * the ones never allocated, so the answer names only the exceptions -- in index order, which is the
     * query's promise. The content hasher sorts for itself rather than rely on it, so what is pinned
     * here is the query, not anything downstream.
     *
     * @throws \Exception
     */
    public function testReportsTheNonValidStatusesByIndexInIndexOrder(): void
    {
        $this->createList();
        $this->createList(self::OTHER_LIST_ID, 2);

        for ($idx = 0; $idx < 6; $idx++) {
            $this->allocate($idx, 'urn:vc:' . $idx);
        }

        $this->allocate(0, 'urn:vc:other', null, null, null, self::OTHER_LIST_ID);

        $this->assertSame([], $this->repository->findNonValidStatuses(self::LIST_ID));

        // Changed out of index order, so that the order of the answer is the query's doing.
        $this->updateStatus(5, StatusTypeEnum::Valid, StatusTypeEnum::Invalid);
        $this->updateStatus(1, StatusTypeEnum::Valid, StatusTypeEnum::Suspended);
        $this->updateStatus(3, StatusTypeEnum::Valid, StatusTypeEnum::Invalid);
        $this->updateStatus(0, StatusTypeEnum::Valid, StatusTypeEnum::Invalid, self::OTHER_LIST_ID);

        $this->assertSame(
            [
                1 => StatusTypeEnum::Suspended->value,
                3 => StatusTypeEnum::Invalid->value,
                5 => StatusTypeEnum::Invalid->value,
            ],
            $this->repository->findNonValidStatuses(self::LIST_ID),
        );
    }


    /**
     * The count is of indices handed out, per list, and it does not go down when a credential expires
     * and its linkage is cleared: the index stays taken, which is the whole reason rows are kept.
     *
     * @throws \Exception
     */
    public function testCountsTheAllocatedIndicesOfOneList(): void
    {
        $this->createList(self::LIST_ID, 1, StatusListExpiryLaneEnum::Expiring);
        $this->createList(self::OTHER_LIST_ID, 2);

        $this->assertSame(0, $this->repository->countAllocated(self::LIST_ID));

        for ($idx = 0; $idx < 3; $idx++) {
            $this->allocate(
                $idx,
                'urn:vc:' . $idx,
                null,
                new DateTimeImmutable('2026-01-01 09:00:00'),
                new DateTimeImmutable('2026-06-01 09:00:00'),
            );
        }

        $this->allocate(0, 'urn:vc:other', null, null, null, self::OTHER_LIST_ID);

        $this->assertSame(3, $this->repository->countAllocated(self::LIST_ID));
        $this->assertSame(1, $this->repository->countAllocated(self::OTHER_LIST_ID));
        $this->assertSame(0, $this->repository->countAllocated('no-such-list'));

        $this->assertSame(3, $this->repository->clearExpiredLinkage(new DateTimeImmutable('2026-08-07 12:00:00'), 10));

        $this->assertSame(3, $this->repository->countAllocated(self::LIST_ID));
    }


    /**
     * A repository whose statements are collected instead of run.
     *
     * The tests above use a real SQLite, which has allowed 32766 bound variables since 3.32 -- so a
     * statement binding more than an older build accepts runs perfectly well there and the tests pass
     * on a database the deployment might not have. Counting what each statement binds is the only way
     * to see that limit from a test at all.
     *
     * The write returns how many rows the statement named, so a caller summing across statements is
     * checked as well: a method which returned the count of only its last statement would be caught.
     *
     * @param list<array<string,mixed>> $bindings Filled with the parameters of every statement written.
     * @param array<array-key,mixed> $selected Rows the repository is told it selected -- or whatever else a
     * driver might hand back, since the tests of the malformed-row guards pass things which are not rows.
     */
    protected function repositoryCollectingStatements(
        array &$bindings,
        array $selected = [],
    ): StatusListEntryRepository {
        $databaseMock = $this->createMock(Database::class);
        $databaseMock->method('applyPrefix')->willReturnCallback(
            static fn(string $table): string => 'phpunit_' . $table,
        );

        $statementMock = $this->createMock(PDOStatement::class);
        $statementMock->method('fetchAll')->willReturn($selected);
        $databaseMock->method('readPrimary')->willReturn($statementMock);

        $databaseMock->method('write')->willReturnCallback(
            /**
             * @param array<string,mixed> $params
             */
            function (string $statement, array $params = []) use (&$bindings): int {
                $bindings[] = $params;

                return count(array_filter(
                    array_keys($params),
                    static fn(string $name): bool => str_starts_with($name, 'idx_'),
                ));
            },
        );

        return new StatusListEntryRepository($this->moduleConfigMock, $databaseMock, null, $this->helpers);
    }


    /**
     * @throws \Exception
     */
    public function testSeedsInStatementsEveryDriverAccepts(): void
    {
        $bindings = [];
        // More than one statement's worth at two bound variables a row, and not a multiple of it, so a
        // short final statement is exercised too.
        $this->repositoryCollectingStatements($bindings)->seed(self::LIST_ID, 1200);

        $this->assertGreaterThan(1, count($bindings));

        $seeded = [];

        foreach ($bindings as $params) {
            $this->assertLessThanOrEqual(self::MAX_BOUND_VARIABLES, count($params));

            foreach ($params as $name => $value) {
                if (str_starts_with($name, 'idx_') && is_array($value)) {
                    $seeded[] = $value[0];
                }
            }
        }

        // Splitting a list across statements must neither skip an index nor hand one out twice, so the
        // whole run is compared rather than counted.
        $this->assertSame(range(0, 1199), $seeded);
    }


    /**
     * @throws \Exception
     */
    public function testClearsLinkageInStatementsEveryDriverAccepts(): void
    {
        $selected = [];

        for ($idx = 0; $idx < 1200; $idx++) {
            $selected[] = ['status_list_id' => self::LIST_ID, 'idx' => $idx];
        }

        $bindings = [];
        $cleared = $this->repositoryCollectingStatements($bindings, $selected)
            ->clearExpiredLinkage(new DateTimeImmutable('2026-08-07 12:00:00'), 1200);

        $this->assertSame(1200, $cleared);
        $this->assertGreaterThan(1, count($bindings));

        $moments = [];

        foreach ($bindings as $params) {
            $this->assertLessThanOrEqual(self::MAX_BOUND_VARIABLES, count($params));
            $this->assertArrayHasKey('updated_at', $params);
            $moments[] = $params['updated_at'];
        }

        // The rows are in several statements only because of how many one can bind, so they are still
        // one clearing and still carry one moment.
        $this->assertCount(1, array_unique($moments));
    }


    /**
     * A bound of nothing is honoured before anything is asked of the database: no select to find rows
     * which will not be touched, and no statement naming none of them.
     *
     * @throws \Exception
     */
    public function testALimitBelowOneIssuesNoStatementAtAll(): void
    {
        $databaseMock = $this->createMock(Database::class);
        $databaseMock->expects($this->never())->method('readPrimary');
        $databaseMock->expects($this->never())->method('write');

        $repository = new StatusListEntryRepository($this->moduleConfigMock, $databaseMock, null, $this->helpers);
        $now = new DateTimeImmutable('2026-08-07 12:00:00');

        $this->assertSame(0, $repository->clearExpiredLinkage($now, 0));
        $this->assertSame(0, $repository->clearExpiredLinkage($now, -1));
        $this->assertSame(0, $repository->deleteRetiredEntries(self::LIST_ID, 0));
        $this->assertSame(0, $repository->deleteRetiredEntries(self::LIST_ID, -1));
    }


    /**
     * The select is the repository's own, so a row it cannot identify is not something production
     * produces; the guard is for a driver returning a shape nothing here expects. What it must not do
     * is name a row it cannot identify, so only the rows carrying a list and a numeric index reach the
     * update, and the numeric one may be a string, as some drivers return it.
     *
     * @throws \Exception
     */
    public function testClearsOnlyTheLinkageOfRowsItCanIdentify(): void
    {
        $selected = [
            ['status_list_id' => self::LIST_ID, 'idx' => 0],
            'not a row',
            ['status_list_id' => self::LIST_ID],
            ['status_list_id' => self::LIST_ID, 'idx' => 'three'],
            ['status_list_id' => ['not', 'scalar'], 'idx' => 4],
            ['status_list_id' => null, 'idx' => 5],
            ['status_list_id' => self::LIST_ID, 'idx' => '6'],
        ];

        $bindings = [];
        $cleared = $this->repositoryCollectingStatements($bindings, $selected)
            ->clearExpiredLinkage(new DateTimeImmutable('2026-08-07 12:00:00'), 10);

        $this->assertSame(2, $cleared);
        $this->assertCount(1, $bindings);
        $this->assertSame(self::LIST_ID, $bindings[0]['list_0']);
        $this->assertSame([0, PDO::PARAM_INT], $bindings[0]['idx_0']);
        $this->assertSame(self::LIST_ID, $bindings[0]['list_1']);
        $this->assertSame([6, PDO::PARAM_INT], $bindings[0]['idx_1']);
        $this->assertArrayNotHasKey('idx_2', $bindings[0]);
    }


    /**
     * @throws \Exception
     */
    public function testClearsNothingAndWritesNothingWhenNoSelectedRowCanBeIdentified(): void
    {
        $bindings = [];
        $cleared = $this->repositoryCollectingStatements($bindings, ['not a row', ['idx' => 'three']])
            ->clearExpiredLinkage(new DateTimeImmutable('2026-08-07 12:00:00'), 10);

        $this->assertSame(0, $cleared);
        $this->assertSame([], $bindings);
    }


    /**
     * The same guard on the read which rebuilds a list: a row without a numeric index and a numeric
     * status is left out rather than written into the list at whatever `(int)` makes of it, and a
     * driver returning both as strings is read as the integers it means.
     *
     * @throws \Exception
     */
    public function testReportsOnlyTheNonValidStatusesItCanRead(): void
    {
        $selected = [
            ['idx' => 3, 'status' => 1],
            'not a row',
            ['idx' => 4],
            ['status' => 2],
            ['idx' => 'five', 'status' => 1],
            ['idx' => 6, 'status' => 'two'],
            ['idx' => '7', 'status' => '2'],
        ];

        $bindings = [];

        $this->assertSame(
            [3 => 1, 7 => 2],
            $this->repositoryCollectingStatements($bindings, $selected)->findNonValidStatuses(self::LIST_ID),
        );
    }


    /**
     * @return array<string,array{array<array-key,mixed>,int}>
     */
    public static function allocatedTotalProvider(): array
    {
        return [
            'an integer' => [[['allocated_total' => 3]], 3],
            'a string of digits, as PDO returns one' => [[['allocated_total' => '3']], 3],
            'no rows' => [[], 0],
            'a row without the column' => [[['entry_total' => 3]], 0],
            'a total which is not a number' => [[['allocated_total' => 'three']], 0],
            'a null total' => [[['allocated_total' => null]], 0],
        ];
    }


    /**
     * A count which cannot be read is zero rather than an error, which is the reading every count in
     * this repository makes.
     *
     * @throws \Exception
     */
    #[DataProvider('allocatedTotalProvider')]
    public function testReadsTheAllocatedTotalAsTheDriverReturnsIt(array $selected, int $expected): void
    {
        $bindings = [];

        $this->assertSame(
            $expected,
            $this->repositoryCollectingStatements($bindings, $selected)->countAllocated(self::LIST_ID),
        );
    }
}

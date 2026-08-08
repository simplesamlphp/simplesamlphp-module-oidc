<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

#[CoversClass(StatusListEntryRepository::class)]
class StatusListEntryRepositoryTest extends TestCase
{
    protected const string LIST_ID = 'a-status-list-id';

    protected const string OTHER_LIST_ID = 'another-status-list-id';

    protected const string CONFIGURATION_ID = 'UniversityDegree';

    protected const int CAPACITY = 8;

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
     * @throws \Exception
     */
    protected function createList(string $id = self::LIST_ID, int $generation = 1): void
    {
        $this->statusListRepository->create(
            $id,
            'https://op.example.org/statuslist/' . $id,
            'default',
            'a-policy-fingerprint',
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
        $this->createList();
        $this->createList(self::OTHER_LIST_ID, 2);

        $this->assertSame(0, $this->repository->countNeverRetiringLists());

        $this->allocate(0, 'urn:vc:expiring', null, null, new DateTimeImmutable('2027-08-07 12:00:00'));

        $this->assertSame(0, $this->repository->countNeverRetiringLists());

        $this->allocate(1, 'urn:vc:permanent');

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
        $this->createList();
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
        $this->createList();
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
        $this->createList();
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
        $this->createList();

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
}

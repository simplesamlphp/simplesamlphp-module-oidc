<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\integration\StatusList;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\StatusChangeSourceEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusAuditRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\DbStatusUpdater;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListAllocationTarget;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;
use SimpleSAML\Test\Module\oidc\integration\DatabaseContainers;

/**
 * Status List storage against each supported database.
 *
 * The unit tests for this storage run on SQLite, which is permissive in ways the other two are not, so
 * several of the things the design rests on are simply not observable there: whether a conditional
 * update reports the rows it matched, how booleans and datetimes survive a round trip, and how a fixed
 * width column treats a short value. Each of those has a different answer per driver, so they get
 * asserted per driver.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\DbStatusIndexAllocatorTest
 */
#[CoversClass(StatusListRepository::class)]
#[CoversClass(StatusListEntryRepository::class)]
#[CoversClass(StatusAuditRepository::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusListStorageTest extends TestCase
{
    protected const string LIST_ID = 'integration-status-list-0000000000000000000000000000000000000000';

    /** A second list of the same pool and policy, used for the lane which LIST_ID is not in. */
    protected const string OTHER_LIST_ID = 'integration-status-list-1111111111111111111111111111111111111111';

    protected const int CAPACITY = 64;


    public static array $pgConfig;

    public static array $mysqlConfig;

    public static array $sqliteConfig;

    protected Database $database;

    protected StatusListRepository $statusListRepository;

    protected StatusListEntryRepository $statusListEntryRepository;


    /**
     * @throws \Exception
     */
    public static function setUpBeforeClass(): void
    {
        Configuration::setConfigDir(__DIR__ . '/../../../config');
        self::$pgConfig = DatabaseContainers::postgres();
        self::$mysqlConfig = DatabaseContainers::mysql();
        self::$sqliteConfig = DatabaseContainers::sqlite();
    }


    /**
     * @param array<string,mixed> $config
     * @throws \Exception
     */
    protected function useDatabase(array $config): void
    {
        $this->database = Database::getInstance(Configuration::loadFromArray($config, '', 'simplesaml'));
        (new DatabaseMigration($this->database))->migrate();

        $this->database->write('DELETE FROM ' . $this->database->applyPrefix('oidc_status_list_entry'));
        $this->database->write('DELETE FROM ' . $this->database->applyPrefix('oidc_status_list'));

        $moduleConfig = new ModuleConfig();
        $helpers = new Helpers();

        $this->statusListRepository = new StatusListRepository($moduleConfig, $this->database, null, $helpers);
        $this->statusListEntryRepository = new StatusListEntryRepository(
            $moduleConfig,
            $this->database,
            null,
            $helpers,
        );
    }

    /**
     * @throws \Exception
     */
    /**
     * The lane defaults to the non-expiring one because most cases here allocate without an expiry, and
     * allocation is refused when the entry's expiry and the list's lane disagree. A case which gives its
     * credentials an expiry has to ask for the expiring lane.
     *
     * @throws \Exception
     */
    protected function givenSeededList(
        int $bits = 2,
        string $allowedStatuses = '0,1,2',
        StatusListExpiryLaneEnum $expiryLane = StatusListExpiryLaneEnum::NonExpiring,
    ): void {
        $this->statusListRepository->create(
            self::LIST_ID,
            'https://op.example.org/module.php/oidc/statuslist/' . self::LIST_ID,
            'integration-pool',
            'integration-fingerprint',
            $expiryLane,
            1,
            $bits,
            self::CAPACITY,
            $allowedStatuses,
            43200,
            604800,
            3600,
            'integration-signing-key',
            StatusListKeyProfileEnum::DidJwk,
        );

        $this->statusListEntryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->statusListRepository->activate(self::LIST_ID);
    }

    /**
     * A newly created list has no published token, which is recorded as an empty content hash rather
     * than as null so that the compare-and-set which publishes the first token has something to match.
     *
     * This is asserted per driver because a fixed width column does not treat a short value the same
     * way everywhere: PostgreSQL blank-pads CHAR and keeps the padding on the way out, so storing this
     * in a CHAR would read back as spaces and never compare equal to an empty string again -- which
     * would leave publication matching no rows, for ever, on PostgreSQL only.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testEmptyContentHashRoundTripsAsAnEmptyString(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $statusList = $this->statusListRepository->findByIdOnPrimary(self::LIST_ID);

        $this->assertSame('', $statusList?->getSignedTokenContentHash());
        $this->assertFalse($statusList?->hasPublishedToken());
    }

    /**
     * Claiming an index is a conditional update, and the number of rows it affected is the whole
     * answer to whether this caller got it. That only works if every driver reports it the same way.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testClaimingAnIndexReportsWhetherItWasFree(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $credentialId = 'https://op.example.org/vc/first';

        $this->assertTrue(
            $this->statusListEntryRepository->allocate(
                self::LIST_ID,
                7,
                $credentialId,
                $this->statusListEntryRepository->hashCredentialId($credentialId),
                'IntegrationCredential',
                'subject-ref',
                null,
            ),
        );

        // The same index a second time must report that it was not free, rather than raising, and
        // rather than overwriting the credential already holding it.
        $this->assertFalse(
            $this->statusListEntryRepository->allocate(
                self::LIST_ID,
                7,
                'https://op.example.org/vc/second',
                $this->statusListEntryRepository->hashCredentialId('https://op.example.org/vc/second'),
                'IntegrationCredential',
                null,
                null,
            ),
        );

        $entry = $this->statusListEntryRepository->findByListAndIdx(self::LIST_ID, 7);
        $this->assertSame($credentialId, $entry?->getCredentialId());
        $this->assertTrue($entry?->isAllocated());

        // Deliberately shorter than the column, since that is what catches blank padding: PostgreSQL
        // pads CHAR and keeps the padding on the way out, so a short value would come back with
        // trailing spaces and never compare equal to what was written.
        $this->assertSame('subject-ref', $entry?->getSubjectRef());
    }

    /**
     * A list which stopped accepting allocations must take no more, which the guard in the same
     * statement enforces. Whether a boolean comparison behaves is driver specific.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testADeactivatedListAcceptsNoFurtherClaims(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $this->assertTrue($this->statusListRepository->deactivate(self::LIST_ID));

        $this->assertFalse(
            $this->statusListEntryRepository->allocate(
                self::LIST_ID,
                9,
                'https://op.example.org/vc/late',
                $this->statusListEntryRepository->hashCredentialId('https://op.example.org/vc/late'),
                'IntegrationCredential',
                null,
                null,
            ),
        );

        // Deactivating is what settles which worker creates the successor, so it must report a winner
        // exactly once.
        $this->assertFalse($this->statusListRepository->deactivate(self::LIST_ID));
    }

    /**
     * Rebuilding a list reads only the entries which are not Valid, keyed on the index they carry.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testReadsBackOnlyTheEntriesWhichAreNotValid(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $updater = new DbStatusUpdater(
            $this->statusListRepository,
            $this->statusListEntryRepository,
            new LoggerService(),
        );

        foreach ([3, 11, 40] as $idx) {
            $this->statusListEntryRepository->allocate(
                self::LIST_ID,
                $idx,
                'https://op.example.org/vc/' . $idx,
                $this->statusListEntryRepository->hashCredentialId('https://op.example.org/vc/' . $idx),
                'IntegrationCredential',
                null,
                null,
            );
        }

        $updater->setStatus(self::LIST_ID, 11, StatusTypeEnum::Invalid);
        $updater->setStatus(self::LIST_ID, 40, StatusTypeEnum::Suspended);

        // Index 3 is allocated but Valid, so it is absent, exactly like the indices never handed out.
        $this->assertSame(
            [11 => StatusTypeEnum::Invalid->value, 40 => StatusTypeEnum::Suspended->value],
            $this->statusListEntryRepository->findNonValidStatuses(self::LIST_ID),
        );

        $this->assertSame(3, $this->statusListEntryRepository->countAllocated(self::LIST_ID));
    }

    /**
     * Changing a status has to mark the published token stale, and the guard on that update means it
     * only reports a change when there was one to make.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testChangingAStatusInvalidatesThePublishedToken(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $this->statusListEntryRepository->allocate(
            self::LIST_ID,
            5,
            'https://op.example.org/vc/five',
            $this->statusListEntryRepository->hashCredentialId('https://op.example.org/vc/five'),
            'IntegrationCredential',
            null,
            null,
        );

        $this->database->write(
            'UPDATE ' . $this->database->applyPrefix('oidc_status_list') .
            ' SET signed_token = :token, signed_token_content_hash = :hash WHERE id = :id',
            [
                'token' => 'header.payload.signature',
                'hash' => str_repeat('a', 64),
                'id' => self::LIST_ID,
            ],
        );

        $this->assertTrue($this->statusListRepository->findByIdOnPrimary(self::LIST_ID)?->hasPublishedToken());

        $updater = new DbStatusUpdater(
            $this->statusListRepository,
            $this->statusListEntryRepository,
            new LoggerService(),
        );
        $updater->setStatus(self::LIST_ID, 5, StatusTypeEnum::Invalid);

        $statusList = $this->statusListRepository->findByIdOnPrimary(self::LIST_ID);
        $this->assertSame('', $statusList?->getSignedTokenContentHash());
        $this->assertFalse($statusList?->hasPublishedToken());
    }

    /**
     * A list still being seeded is found by the in-preparation lookup while it is recent, and ignored
     * once it is old enough to count as abandoned. The comparison is against a datetime bound as a
     * string, which is the part that differs between drivers.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testFindsAListBeingPreparedOnlyWhileItIsRecent(string $database): void
    {
        $this->useDatabase(self::$$database);

        // Created but never opened, which is what a seed in progress looks like.
        $this->statusListRepository->create(
            self::LIST_ID,
            'https://op.example.org/module.php/oidc/statuslist/' . self::LIST_ID,
            'integration-pool',
            'integration-fingerprint',
            StatusListExpiryLaneEnum::Expiring,
            1,
            2,
            self::CAPACITY,
            '0,1,2',
            43200,
            604800,
            3600,
            'integration-signing-key',
            StatusListKeyProfileEnum::DidJwk,
        );

        $helpers = new Helpers();

        $this->assertCount(
            1,
            $this->statusListRepository->findBeingPreparedForPolicy(
                'integration-pool',
                'integration-fingerprint',
                StatusListExpiryLaneEnum::Expiring,
                $helpers->dateTime()->getUtc()->sub(new DateInterval('PT2M')),
            ),
        );

        // Same list, asked about with a cut-off it is older than.
        $this->assertCount(
            0,
            $this->statusListRepository->findBeingPreparedForPolicy(
                'integration-pool',
                'integration-fingerprint',
                StatusListExpiryLaneEnum::Expiring,
                $helpers->dateTime()->getUtc()->add(new DateInterval('PT2M')),
            ),
        );

        // A list which is already open is not one being prepared.
        $this->statusListRepository->activate(self::LIST_ID);
        $this->assertCount(
            0,
            $this->statusListRepository->findBeingPreparedForPolicy(
                'integration-pool',
                'integration-fingerprint',
                StatusListExpiryLaneEnum::Expiring,
                $helpers->dateTime()->getUtc()->sub(new DateInterval('PT2M')),
            ),
        );
    }

    /**
     * Only a list which was never opened may be removed, so that one a credential could point at is
     * untouchable.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testRemovesOnlyAListWhichWasNeverOpened(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $this->assertFalse($this->statusListRepository->deleteUnopened(self::LIST_ID));
        $this->assertNotNull($this->statusListRepository->findByIdOnPrimary(self::LIST_ID));
    }

    /**
     * Removing an unopened list takes its entries with it on every driver.
     *
     * The foreign key is declared ON DELETE CASCADE, but SQLite enforces foreign keys only when the
     * connection asks it to and this module's database wrapper does not, so the cascade does nothing
     * there. The entries are therefore removed explicitly, and this asserts that they are actually gone
     * rather than that the constraint fired.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testRemovingAnUnopenedListRemovesItsEntries(string $database): void
    {
        $this->useDatabase(self::$$database);

        $this->statusListRepository->create(
            self::LIST_ID,
            'https://op.example.org/module.php/oidc/statuslist/' . self::LIST_ID,
            'integration-pool',
            'integration-fingerprint',
            StatusListExpiryLaneEnum::Expiring,
            1,
            2,
            self::CAPACITY,
            '0,1,2',
            43200,
            604800,
            3600,
            'integration-signing-key',
            StatusListKeyProfileEnum::DidJwk,
        );
        $this->statusListEntryRepository->seed(self::LIST_ID, self::CAPACITY);

        $this->assertTrue($this->statusListRepository->deleteUnopened(self::LIST_ID));
        $this->assertNull($this->statusListRepository->findByIdOnPrimary(self::LIST_ID));

        $remaining = $this->database->readPrimary(
            'SELECT COUNT(*) AS total FROM ' . $this->database->applyPrefix('oidc_status_list_entry') .
            ' WHERE status_list_id = :id',
            ['id' => self::LIST_ID],
        )->fetchAll();

        $this->assertSame(0, (int)($remaining[0]['total'] ?? -1));
    }

    /**
     * Publishing is a compare-and-set against the hash the signer observed, and the number of rows it
     * affected is the whole answer to whether this signer won. That only works if every driver reports
     * it the same way, and if the initial empty hash survives a round trip well enough to be matched.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testPublishingIsSettledByTheObservedContentHash(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $issuedAt = (new Helpers())->dateTime()->getUtc();
        $expiresAt = $issuedAt->add(new DateInterval('P7D'));
        $firstHash = str_repeat('a', 64);

        // The first publication observes the empty hash a newly created list carries.
        $this->assertTrue(
            $this->statusListRepository->publishToken(
                self::LIST_ID,
                '',
                0,
                $firstHash,
                'first.published.token',
                $issuedAt,
                $expiresAt,
            ),
        );

        // A second signer which began from that same empty hash no longer matches, so its token is not
        // published over the one already there.
        $this->assertFalse(
            $this->statusListRepository->publishToken(
                self::LIST_ID,
                '',
                0,
                str_repeat('b', 64),
                'second.published.token',
                $issuedAt,
                $expiresAt,
            ),
        );

        $statusList = $this->statusListRepository->findByIdOnPrimary(self::LIST_ID);
        $this->assertSame('first.published.token', $statusList?->getSignedToken());
        $this->assertSame($firstHash, $statusList?->getSignedTokenContentHash());
        $this->assertTrue($statusList?->hasPublishedToken());
    }

    /**
     * Re-signing unchanged content compares a hash against itself, which settles nothing on its own, so
     * the issuance time has to be the tie-break. A signer whose token is not newer than what is
     * published must lose.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testRefreshingUnchangedContentRequiresANewerIssuanceTime(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $hash = str_repeat('c', 64);
        $issuedAt = (new Helpers())->dateTime()->getUtc();
        $expiresAt = $issuedAt->add(new DateInterval('P7D'));

        $this->assertTrue(
            $this->statusListRepository->publishToken(
                self::LIST_ID,
                '',
                0,
                $hash,
                'first.published.token',
                $issuedAt,
                $expiresAt,
            ),
        );

        // Same content, and no later than what is published: nothing to do.
        $this->assertFalse(
            $this->statusListRepository->publishToken(
                self::LIST_ID,
                $hash,
                0,
                $hash,
                'stale.refresh.token',
                $issuedAt->sub(new DateInterval('PT1H')),
                $expiresAt,
            ),
        );

        // Same content, genuinely later: this is the refresh.
        $this->assertTrue(
            $this->statusListRepository->publishToken(
                self::LIST_ID,
                $hash,
                0,
                $hash,
                'refreshed.token',
                $issuedAt->add(new DateInterval('PT1H')),
                $expiresAt->add(new DateInterval('PT1H')),
            ),
        );

        $this->assertSame(
            'refreshed.token',
            $this->statusListRepository->findByIdOnPrimary(self::LIST_ID)?->getSignedToken(),
        );
    }

    /**
     * The case the content hash cannot settle on its own. A signer which observed the empty hash, and
     * whose snapshot a revocation superseded while it was signing, must not publish -- and the
     * revocation leaves the hash exactly as it found it, empty, so only the counter distinguishes them.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testAnInvalidationDuringSigningBlocksPublicationEvenWhileTheHashIsEmpty(
        string $database,
    ): void {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $issuedAt = (new Helpers())->dateTime()->getUtc();
        $expiresAt = $issuedAt->add(new DateInterval('P7D'));

        // What a signer reads before it starts: nothing published, and the counter as it stands.
        $observed = $this->statusListRepository->findByIdOnPrimary(self::LIST_ID);
        $this->assertSame('', $observed?->getSignedTokenContentHash());
        $observedCounter = (int)$observed?->getInvalidationCounter();

        // A revocation lands while that signer is signing. The hash it clears is already clear.
        $this->statusListRepository->invalidatePublishedToken(self::LIST_ID);

        $this->assertSame(
            '',
            $this->statusListRepository->findByIdOnPrimary(self::LIST_ID)?->getSignedTokenContentHash(),
        );
        $this->assertSame(
            $observedCounter + 1,
            $this->statusListRepository->findByIdOnPrimary(self::LIST_ID)?->getInvalidationCounter(),
        );

        $this->assertFalse(
            $this->statusListRepository->publishToken(
                self::LIST_ID,
                '',
                $observedCounter,
                str_repeat('e', 64),
                'token.built.before.the.revocation',
                $issuedAt,
                $expiresAt,
            ),
        );

        $this->assertNull($this->statusListRepository->findByIdOnPrimary(self::LIST_ID)?->getSignedToken());
    }

    /**
     * Only lists with something published are candidates for reconciliation, and retired ones are not
     * served at all.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testFindsOnlyListsWhichHaveAPublishedToken(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $this->assertSame([], $this->statusListRepository->findPublished(10));

        $issuedAt = (new Helpers())->dateTime()->getUtc();

        $this->statusListRepository->publishToken(
            self::LIST_ID,
            '',
            0,
            str_repeat('d', 64),
            'a.published.token',
            $issuedAt,
            $issuedAt->add(new DateInterval('P7D')),
        );

        $published = $this->statusListRepository->findPublished(10);
        $this->assertCount(1, $published);
        $this->assertSame(self::LIST_ID, $published[0]->getId());

        // A list whose token has been invalidated has nothing to reconcile against.
        $this->statusListRepository->invalidatePublishedToken(self::LIST_ID);
        $this->assertSame([], $this->statusListRepository->findPublished(10));
    }

    /**
     * The reconciler clears a token only while it is still the one it examined, so that a token
     * published in the meantime -- which is by definition current -- is left alone rather than
     * needlessly re-signed.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testGuardedInvalidationOnlyClearsTheTokenItExamined(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $issuedAt = (new Helpers())->dateTime()->getUtc();
        $examinedHash = str_repeat('f', 64);

        $this->statusListRepository->publishToken(
            self::LIST_ID,
            '',
            0,
            $examinedHash,
            'the.examined.token',
            $issuedAt,
            $issuedAt->add(new DateInterval('P7D')),
        );

        // A hash which is not the one on the row: this token is not the one that was examined.
        $this->assertFalse(
            $this->statusListRepository->invalidatePublishedTokenIfUnchanged(
                self::LIST_ID,
                str_repeat('0', 64),
                0,
            ),
        );
        $this->assertTrue($this->statusListRepository->findByIdOnPrimary(self::LIST_ID)?->hasPublishedToken());

        // The right hash but a counter which has moved on: likewise not the one examined.
        $this->assertFalse(
            $this->statusListRepository->invalidatePublishedTokenIfUnchanged(self::LIST_ID, $examinedHash, 7),
        );
        $this->assertTrue($this->statusListRepository->findByIdOnPrimary(self::LIST_ID)?->hasPublishedToken());

        $this->assertTrue(
            $this->statusListRepository->invalidatePublishedTokenIfUnchanged(self::LIST_ID, $examinedHash, 0),
        );

        $statusList = $this->statusListRepository->findByIdOnPrimary(self::LIST_ID);
        $this->assertSame('', $statusList?->getSignedTokenContentHash());
        $this->assertSame(1, $statusList?->getInvalidationCounter());
    }


    /**
     * @throws \Exception
     */
    protected function givenAllocatedEntry(
        int $idx,
        string $credentialId,
        ?DateTimeImmutable $expiresAt,
        string $statusListId = self::LIST_ID,
    ): void {
        // Asserted rather than ignored: the lane guard refuses an allocation whose expiry does not match
        // the list, and a fixture which silently failed to create its entry would leave the case it was
        // setting up untested while still passing.
        $this->assertTrue(
            $this->statusListEntryRepository->allocate(
                $statusListId,
                $idx,
                $credentialId,
                $this->statusListEntryRepository->hashCredentialId($credentialId),
                'IntegrationCredential',
                'a-subject-ref',
                $expiresAt,
            ),
        );
    }


    /**
     * A second list, in the non-expiring lane, for the cases which need an entry of each kind. They can
     * no longer share one list, which is the point of the lane.
     *
     * @throws \Exception
     */
    protected function givenSeededNonExpiringList(): void
    {
        $this->statusListRepository->create(
            self::OTHER_LIST_ID,
            'https://op.example.org/module.php/oidc/statuslist/' . self::OTHER_LIST_ID,
            'integration-pool',
            'integration-fingerprint',
            StatusListExpiryLaneEnum::NonExpiring,
            1,
            2,
            self::CAPACITY,
            '0,1,2',
            43200,
            604800,
            3600,
            'integration-signing-key',
            StatusListKeyProfileEnum::DidJwk,
        );

        $this->statusListEntryRepository->seed(self::OTHER_LIST_ID, self::CAPACITY);
        $this->statusListRepository->activate(self::OTHER_LIST_ID);
    }


    /**
     * @return array<string,mixed>
     */
    protected function readEntry(int $idx, string $statusListId = self::LIST_ID): array
    {
        $rows = $this->database->readPrimary(
            sprintf(
                'SELECT * FROM %s WHERE status_list_id = :status_list_id AND idx = :idx',
                $this->database->applyPrefix('oidc_status_list_entry'),
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
     * Clearing the linkage of an expired credential is bounded, and the bound has to be applied in the
     * SELECT: MySQL accepts a LIMIT on an UPDATE and PostgreSQL rejects it outright. The update which
     * follows names its rows by composite key, one placeholder per value, since a repeated named
     * placeholder binds only its first occurrence on some drivers.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testClearsTheLinkageOfExpiredCredentialsInBoundedBatches(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList(expiryLane: StatusListExpiryLaneEnum::Expiring);
        // The credential which never expires goes in the other lane's list, since the two kinds can no
        // longer share one. Clearing runs across every list, so it still has to step over this one.
        $this->givenSeededNonExpiringList();

        for ($idx = 0; $idx < 3; $idx++) {
            $this->givenAllocatedEntry($idx, 'urn:vc:expired:' . $idx, new DateTimeImmutable('2020-01-01 09:00:00'));
        }
        $this->givenAllocatedEntry(9, 'urn:vc:live', new DateTimeImmutable('2099-01-01 09:00:00'));
        $this->givenAllocatedEntry(10, 'urn:vc:permanent', null, self::OTHER_LIST_ID);

        $now = new DateTimeImmutable('2026-08-07 12:00:00');

        $this->assertSame(2, $this->statusListEntryRepository->clearExpiredLinkage($now, 2));
        $this->assertSame(1, $this->statusListEntryRepository->clearExpiredLinkage($now, 2));
        $this->assertSame(0, $this->statusListEntryRepository->clearExpiredLinkage($now, 2));

        $cleared = $this->readEntry(0);
        $this->assertNull($cleared['credential_id']);
        $this->assertNull($cleared['credential_id_hash']);
        $this->assertNull($cleared['credential_configuration_id']);
        $this->assertNull($cleared['subject_ref']);
        // What the published token is built from, and what stops the index being handed out again.
        $this->assertSame(0, (int)$cleared['idx']);
        $this->assertNotNull($cleared['expires_at']);

        $this->assertSame('urn:vc:live', $this->readEntry(9)['credential_id']);
        $this->assertSame(
            'urn:vc:permanent',
            $this->readEntry(10, self::OTHER_LIST_ID)['credential_id'],
        );
    }

    /**
     * Whether anything is still holding the list is tested inside the statement which retires it, as a
     * correlated NOT EXISTS across the two tables. Asserted per driver because that is where a caller
     * reading first and retiring second would leave a gap, and because a guard which did not filter on
     * allocation would refuse every list there is -- each of them has a whole capacity of unallocated
     * indices, none of which has an expiry.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testRetirementItselfRefusesAListWhichIsStillHoldingSomething(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList(expiryLane: StatusListExpiryLaneEnum::Expiring);

        // Allocated before the list is deactivated, since a deactivated list takes no more claims. A
        // credential which never expires would belong to the other lane's list, and its own effect on
        // retirement is covered by testOffersOnlyRetirementCandidatesWhichCouldActuallyBeRetired.
        $this->givenAllocatedEntry(0, 'urn:vc:live', new DateTimeImmutable('2027-02-01 09:00:00'));
        $this->statusListRepository->deactivate(self::LIST_ID);

        $cutOff = new DateTimeImmutable('2026-08-07 12:00:00');

        $this->assertFalse($this->statusListRepository->retire(self::LIST_ID, $cutOff));

        // Both of those brought forward to before the cut-off, leaving only unallocated indices without
        // an expiry -- which must not keep the list from retiring.
        $this->database->write(
            sprintf(
                'UPDATE %s SET expires_at = :expires_at WHERE status_list_id = :status_list_id ' .
                'AND allocated = :allocated',
                $this->database->applyPrefix('oidc_status_list_entry'),
            ),
            [
                'expires_at' => '2021-01-01 09:00:00',
                'status_list_id' => self::LIST_ID,
                'allocated' => true,
            ],
        );

        $this->assertTrue($this->statusListRepository->retire(self::LIST_ID, $cutOff));
    }

    /**
     * The candidate query joins the two tables through a correlated NOT EXISTS, which is what keeps a
     * list that can never be retired from occupying the batches a run is willing to work through.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testOffersOnlyRetirementCandidatesWhichCouldActuallyBeRetired(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();
        $this->givenAllocatedEntry(0, 'urn:vc:permanent', null);
        $this->statusListRepository->deactivate(self::LIST_ID);

        $this->database->write(
            sprintf(
                'UPDATE %s SET deactivated_at = :deactivated_at WHERE id = :id',
                $this->database->applyPrefix('oidc_status_list'),
            ),
            [
                'deactivated_at' => '2020-01-01 09:00:00',
                'id' => self::LIST_ID,
            ],
        );

        $cutOff = new DateTimeImmutable('2026-08-07 12:00:00');

        $this->assertSame([], $this->statusListRepository->findRetirementCandidates($cutOff, 10));

        // The same list once the credential which never expires has an expiry after all.
        $this->database->write(
            sprintf(
                'UPDATE %s SET expires_at = :expires_at WHERE status_list_id = :status_list_id AND idx = :idx',
                $this->database->applyPrefix('oidc_status_list_entry'),
            ),
            [
                'expires_at' => '2021-01-01 09:00:00',
                'status_list_id' => self::LIST_ID,
                'idx' => 0,
            ],
        );

        $this->assertSame([self::LIST_ID], $this->statusListRepository->findRetirementCandidates($cutOff, 10));
    }

    /**
     * Retirement gives back the published token in the same statement which stamps the list, and moves
     * the invalidation counter so a signer mid-flight can not publish onto a list retired underneath it.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testRetirementStampsTheListAndGivesBackItsToken(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();

        $this->statusListRepository->publishToken(
            self::LIST_ID,
            '',
            0,
            str_repeat('a', 64),
            'a.signed.token',
            new DateTimeImmutable('2026-08-01 09:00:00'),
            new DateTimeImmutable('2026-08-08 09:00:00'),
        );
        $this->statusListRepository->deactivate(self::LIST_ID);

        $spentBefore = new DateTimeImmutable('2099-01-01 00:00:00');

        $this->assertTrue($this->statusListRepository->retire(self::LIST_ID, $spentBefore));
        // Only the first caller reports it, so of several workers deciding at once one acts.
        $this->assertFalse($this->statusListRepository->retire(self::LIST_ID, $spentBefore));

        $statusList = $this->statusListRepository->findByIdOnPrimary(self::LIST_ID);

        $this->assertTrue($statusList?->isRetired());
        $this->assertNull($statusList?->getSignedToken());
        $this->assertSame('', $statusList?->getSignedTokenContentHash());
        $this->assertSame(1, $statusList?->getInvalidationCounter());
    }

    /**
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testRemovesTheEntriesOfARetiredListInBoundedRuns(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList();
        $this->statusListRepository->deactivate(self::LIST_ID);
        $this->statusListRepository->retire(self::LIST_ID, new DateTimeImmutable('2099-01-01 00:00:00'));

        $this->assertSame([self::LIST_ID], $this->statusListRepository->findRetiredWithEntries(
            10,
            new DateTimeImmutable('2099-01-01 00:00:00'),
        ));

        $removed = 0;

        while (($inBatch = $this->statusListEntryRepository->deleteRetiredEntries(self::LIST_ID, 25)) > 0) {
            $removed += $inBatch;
        }

        $this->assertSame(self::CAPACITY, $removed);
        // Has to stop being offered, or every list a deployment ever retired is re-examined for ever.
        $this->assertSame([], $this->statusListRepository->findRetiredWithEntries(
            10,
            new DateTimeImmutable('2099-01-01 00:00:00'),
        ));
    }

    /**
     * Deactivating the lists a changed configuration would no longer allocate into is one statement
     * whose exclusion is built from a placeholder triple per current target, and an empty configuration
     * drops the exclusion altogether rather than emitting a `NOT IN ()` no driver accepts.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testDeactivatesOnlyTheListsTheCurrentPolicyWouldNotAllocateInto(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList(expiryLane: StatusListExpiryLaneEnum::Expiring);

        $this->assertSame(
            0,
            $this->statusListRepository->deactivateSuperseded([
                new StatusListAllocationTarget(
                    'integration-pool',
                    'integration-fingerprint',
                    StatusListExpiryLaneEnum::Expiring,
                ),
            ]),
        );
        $this->assertTrue($this->statusListRepository->findByIdOnPrimary(self::LIST_ID)?->isActive());

        // The lane alone is enough to supersede a list, with the pool and the policy unchanged. This is
        // the transition an operator makes by removing the last credential lifetime from a pool, and
        // getting it wrong leaves the old list active, unreachable, and never retired.
        $this->assertSame(
            1,
            $this->statusListRepository->deactivateSuperseded([
                new StatusListAllocationTarget(
                    'integration-pool',
                    'integration-fingerprint',
                    StatusListExpiryLaneEnum::NonExpiring,
                ),
            ]),
        );

        $statusList = $this->statusListRepository->findByIdOnPrimary(self::LIST_ID);
        $this->assertFalse($statusList?->isActive());
        $this->assertNotNull($statusList?->getDeactivatedAt());
    }

    /**
     * The two lanes of one pool and policy are separate allocation targets on every driver, which is what
     * the unique constraint has to permit and what selection has to distinguish.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testKeepsTheTwoLanesOfOnePoolApart(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList(expiryLane: StatusListExpiryLaneEnum::Expiring);

        // Same pool, same policy, same generation, other lane: allowed, because the uniqueness is
        // declared over the lane too.
        $this->statusListRepository->create(
            self::OTHER_LIST_ID,
            'https://op.example.org/module.php/oidc/statuslist/' . self::OTHER_LIST_ID,
            'integration-pool',
            'integration-fingerprint',
            StatusListExpiryLaneEnum::NonExpiring,
            1,
            2,
            self::CAPACITY,
            '0,1,2',
            43200,
            604800,
            3600,
            'integration-signing-key',
            StatusListKeyProfileEnum::DidJwk,
        );
        $this->statusListRepository->activate(self::OTHER_LIST_ID);

        $expiring = $this->statusListRepository->findActiveForPolicy(
            'integration-pool',
            'integration-fingerprint',
            StatusListExpiryLaneEnum::Expiring,
        );
        $nonExpiring = $this->statusListRepository->findActiveForPolicy(
            'integration-pool',
            'integration-fingerprint',
            StatusListExpiryLaneEnum::NonExpiring,
        );

        $this->assertCount(1, $expiring);
        $this->assertCount(1, $nonExpiring);
        $this->assertSame(self::LIST_ID, $expiring[0]->getId());
        $this->assertSame(self::OTHER_LIST_ID, $nonExpiring[0]->getId());

        // And the generation counter is read over the same scope, so neither lane pushes the other along.
        $this->assertSame(
            1,
            $this->statusListRepository->getHighestGeneration(
                'integration-pool',
                'integration-fingerprint',
                StatusListExpiryLaneEnum::Expiring,
            ),
        );
        $this->assertSame(
            1,
            $this->statusListRepository->getHighestGeneration(
                'integration-pool',
                'integration-fingerprint',
                StatusListExpiryLaneEnum::NonExpiring,
            ),
        );
    }

    /**
     * The invariant monitor, on every driver: its two correlated subqueries and the boolean comparison in
     * each are the parts most likely to differ between them.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testCountsLaneMismatchesOnEveryDriver(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenSeededList(expiryLane: StatusListExpiryLaneEnum::Expiring);

        $this->statusListEntryRepository->allocate(
            self::LIST_ID,
            0,
            'urn:vc:expiring',
            $this->statusListEntryRepository->hashCredentialId('urn:vc:expiring'),
            'IntegrationCredential',
            null,
            new DateTimeImmutable('2027-08-07 12:00:00'),
        );

        $this->assertSame(0, $this->statusListEntryRepository->countLaneMismatches());

        // Forced past the guard, since nothing in the module can produce this state; the monitor exists
        // for the case where something did anyway.
        $this->database->write(
            sprintf(
                'UPDATE %s SET expires_at = NULL WHERE status_list_id = :status_list_id AND idx = :idx',
                $this->statusListEntryRepository->getTableName(),
            ),
            ['status_list_id' => self::LIST_ID, 'idx' => 0],
        );

        $this->assertSame(1, $this->statusListEntryRepository->countLaneMismatches());
    }

    /**
     * The audit prune is bounded the same way the linkage clearing is, for the same reason, and deletes
     * by identifier because that is the only shape every driver takes.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testPrunesTheAuditTrailInBoundedBatches(string $database): void
    {
        $this->useDatabase(self::$$database);

        $auditRepository = new StatusAuditRepository(new ModuleConfig(), $this->database, null, new Helpers());
        $this->database->write('DELETE FROM ' . $auditRepository->getTableName());

        for ($idx = 0; $idx < 3; $idx++) {
            $auditRepository->record(
                str_repeat((string)$idx, 64),
                self::LIST_ID,
                $idx,
                StatusTypeEnum::Valid->value,
                StatusTypeEnum::Invalid->value,
                StatusChangeSourceEnum::Api,
                'HR system',
                new DateTimeImmutable('2020-01-01 09:00:00', new DateTimeZone('UTC')),
            );
        }

        $auditRepository->record(
            str_repeat('f', 64),
            self::LIST_ID,
            9,
            StatusTypeEnum::Valid->value,
            StatusTypeEnum::Invalid->value,
            StatusChangeSourceEnum::Admin,
            'jane.doe',
            new DateTimeImmutable('2026-08-01 09:00:00', new DateTimeZone('UTC')),
        );

        $cutOff = new DateTimeImmutable('2026-01-01 00:00:00', new DateTimeZone('UTC'));

        $this->assertSame(2, $auditRepository->removeOlderThan($cutOff, 2));
        $this->assertSame(1, $auditRepository->removeOlderThan($cutOff, 2));
        $this->assertSame(0, $auditRepository->removeOlderThan($cutOff, 2));

        $remaining = $this->database->readPrimary(
            'SELECT idx FROM ' . $auditRepository->getTableName(),
        )->fetchAll();

        $this->assertCount(1, $remaining);
        $this->assertSame(9, (int)$remaining[0]['idx']);
    }

    /**
     * Migrations must be re-runnable, because a version is recorded only once its whole method has
     * succeeded and nothing rolls back what it managed before failing.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testMigrationsAreIdempotent(string $database): void
    {
        $this->useDatabase(self::$$database);

        $migration = new DatabaseMigration($this->database);
        $migration->migrate();
        $migration->migrate();

        $this->assertTrue($migration->isMigrated());
        $this->assertSame([], $migration->getNotImplementedVersions());
    }

    /**
     * A migration interrupted between doing its work and recording that it did.
     *
     * The version is written by a separate statement afterwards, so a process dying in between leaves
     * the column added and the version still pending. Every later run would then fail on a duplicate
     * column until somebody repaired the schema by hand, which is why the migration checks the catalog
     * first. Removing the version row is exactly what that interruption leaves behind.
     *
     * Run with a prefix which is not all lower case, because that is what can make the check answer
     * wrongly: PostgreSQL folds unquoted identifiers, so the table is stored under a name different
     * from the one asked for, and a catalog lookup for the name as written finds nothing. A lower case
     * prefix cannot show that up, since folding it changes nothing.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testAnInterruptedColumnMigrationCanBeRerun(string $database): void
    {
        $config = self::$$database;
        $config['database.prefix'] = 'PhpUnitMixed_';

        $this->useDatabase($config);

        $migration = new DatabaseMigration($this->database);
        $migration->migrate();
        $this->assertTrue($migration->isMigrated());

        // The column is there, but as far as the versions table is concerned the migration never ran.
        $this->database->write(
            'DELETE FROM ' . $this->database->applyPrefix('oidc_migration_versions') .
            ' WHERE version = :version',
            ['version' => '20260801000004'],
        );
        // Reported as the method which would run, and keyed by its position among the class's methods.
        $this->assertSame(
            ['version20260801000004'],
            array_values($migration->getNotImplementedVersions()),
        );

        $migration->migrate();

        $this->assertTrue($migration->isMigrated());
        $this->assertSame([], $migration->getNotImplementedVersions());
    }


    /**
     * @return array<string,array{string}>
     */
    public static function databaseToTest(): array
    {
        return DatabaseContainers::all();
    }
}

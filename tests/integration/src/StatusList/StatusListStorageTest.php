<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\integration\StatusList;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\DbStatusUpdater;
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
class StatusListStorageTest extends TestCase
{
    protected const string LIST_ID = 'integration-status-list-0000000000000000000000000000000000000000';

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
    protected function givenSeededList(int $bits = 2, string $allowedStatuses = '0,1,2'): void
    {
        $this->statusListRepository->create(
            self::LIST_ID,
            'https://op.example.org/module.php/oidc/statuslist/' . self::LIST_ID,
            'integration-pool',
            'integration-fingerprint',
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
                $helpers->dateTime()->getUtc()->sub(new \DateInterval('PT2M')),
            ),
        );

        // Same list, asked about with a cut-off it is older than.
        $this->assertCount(
            0,
            $this->statusListRepository->findBeingPreparedForPolicy(
                'integration-pool',
                'integration-fingerprint',
                $helpers->dateTime()->getUtc()->add(new \DateInterval('PT2M')),
            ),
        );

        // A list which is already open is not one being prepared.
        $this->statusListRepository->activate(self::LIST_ID);
        $this->assertCount(
            0,
            $this->statusListRepository->findBeingPreparedForPolicy(
                'integration-pool',
                'integration-fingerprint',
                $helpers->dateTime()->getUtc()->sub(new \DateInterval('PT2M')),
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
     * @return array<string,array{string}>
     */
    public static function databaseToTest(): array
    {
        return DatabaseContainers::all();
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Exceptions\StatusConflictException;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\DbStatusUpdater;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

/**
 * Run against a real SQLite database, since what matters here is which rows the conditional updates
 * actually match.
 */
#[CoversClass(DbStatusUpdater::class)]
#[AllowMockObjectsWithoutExpectations]
class DbStatusUpdaterTest extends TestCase
{
    protected const string LIST_ID = 'list-1';

    protected const int CAPACITY = 8;


    protected Database $database;

    protected StatusListRepository $statusListRepository;

    protected StatusListEntryRepository $statusListEntryRepository;

    protected MockObject $loggerServiceMock;


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
        $this->database = Database::getInstance();
        $this->database->write('DELETE FROM ' . $this->database->applyPrefix('oidc_status_list_entry'));
        $this->database->write('DELETE FROM ' . $this->database->applyPrefix('oidc_status_list'));

        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $helpers = new Helpers();

        $this->statusListRepository = new StatusListRepository(
            $moduleConfigMock,
            $this->database,
            $protocolCacheMock,
            $helpers,
        );
        $this->statusListEntryRepository = new StatusListEntryRepository(
            $moduleConfigMock,
            $this->database,
            $protocolCacheMock,
            $helpers,
        );
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }


    protected function sut(): DbStatusUpdater
    {
        return new DbStatusUpdater(
            $this->statusListRepository,
            $this->statusListEntryRepository,
            $this->loggerServiceMock,
        );
    }


    /**
     * @throws \Exception
     */
    protected function givenList(int $bits = 2, string $allowedStatuses = '0,1,2'): void
    {
        $this->statusListRepository->create(
            self::LIST_ID,
            'https://op.example.org/module.php/oidc/statuslist/' . self::LIST_ID,
            'pool',
            'fingerprint',
            StatusListExpiryLaneEnum::NonExpiring,
            1,
            $bits,
            self::CAPACITY,
            $allowedStatuses,
            43200,
            604800,
            3600,
            'signing-key-1',
            StatusListKeyProfileEnum::DidJwk,
        );

        $this->statusListEntryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->statusListRepository->activate(self::LIST_ID);
    }


    /**
     * @throws \Exception
     */
    protected function givenAllocatedEntry(int $idx = 3): void
    {
        $this->statusListEntryRepository->allocate(
            self::LIST_ID,
            $idx,
            'https://op.example.org/vc/abc',
            $this->statusListEntryRepository->hashCredentialId('https://op.example.org/vc/abc'),
            'TestCredential',
            null,
            null,
        );
    }


    /**
     * @throws \Exception
     */
    protected function givenPublishedToken(string $contentHash = 'published-hash'): void
    {
        $this->database->write(
            'UPDATE ' . $this->database->applyPrefix('oidc_status_list') .
            ' SET signed_token = :token, signed_token_content_hash = :hash WHERE id = :id',
            ['token' => 'a.b.c', 'hash' => $contentHash, 'id' => self::LIST_ID],
        );
    }


    /**
     * @throws \Exception
     */
    public function testChangesTheStatusOfAnAllocatedEntry(): void
    {
        $this->givenList();
        $this->givenAllocatedEntry();

        $this->assertTrue($this->sut()->setStatus(self::LIST_ID, 3, StatusTypeEnum::Invalid));

        $this->assertSame(
            StatusTypeEnum::Invalid->value,
            $this->statusListEntryRepository->findByListAndIdx(self::LIST_ID, 3)?->getStatus(),
        );
        $this->assertSame(StatusTypeEnum::Invalid->value, $this->sut()->getStatusValue(self::LIST_ID, 3));
    }


    /**
     * The published token has to stop counting as current the moment the content it was signed over
     * changes, or the endpoint would keep serving a token reporting the old status.
     *
     * @throws \Exception
     */
    public function testInvalidatesThePublishedTokenAfterAChange(): void
    {
        $this->givenList();
        $this->givenAllocatedEntry();
        $this->givenPublishedToken();

        $this->sut()->setStatus(self::LIST_ID, 3, StatusTypeEnum::Invalid);

        $this->assertSame(
            '',
            $this->statusListRepository->findByIdOnPrimary(self::LIST_ID)?->getSignedTokenContentHash(),
        );
    }


    /**
     * Repeating a revocation is expected to be harmless, and must not cost a re-sign of the whole list.
     *
     * @throws \Exception
     */
    public function testSettingTheStatusItAlreadyHoldsChangesNothing(): void
    {
        $this->givenList();
        $this->givenAllocatedEntry();
        $this->sut()->setStatus(self::LIST_ID, 3, StatusTypeEnum::Invalid);
        $this->givenPublishedToken();

        $this->assertFalse($this->sut()->setStatus(self::LIST_ID, 3, StatusTypeEnum::Invalid));

        // The published token is left alone, since what it was signed over did not change.
        $this->assertSame(
            'published-hash',
            $this->statusListRepository->findByIdOnPrimary(self::LIST_ID)?->getSignedTokenContentHash(),
        );
    }


    /**
     * An index which was never handed out does not describe any credential, so setting its status would
     * be making a statement about something which does not exist.
     *
     * @throws \Exception
     */
    public function testRefusesToChangeAnUnallocatedEntry(): void
    {
        $this->givenList();

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('never allocated');

        $this->sut()->setStatus(self::LIST_ID, 3, StatusTypeEnum::Invalid);
    }


    /**
     * @throws \Exception
     */
    public function testReportsNoStatusForAnUnallocatedEntry(): void
    {
        $this->givenList();

        $this->assertNull($this->sut()->getStatusValue(self::LIST_ID, 3));
    }


    /**
     * @throws \Exception
     */
    public function testRaisesForAnIndexOutsideTheList(): void
    {
        $this->givenList();

        $this->expectException(StatusListException::class);

        $this->sut()->setStatus(self::LIST_ID, self::CAPACITY + 1, StatusTypeEnum::Invalid);
    }


    /**
     * @throws \Exception
     */
    public function testRaisesForAListWhichDoesNotExist(): void
    {
        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('not found');

        $this->sut()->setStatus('no-such-list', 0, StatusTypeEnum::Invalid);
    }


    /**
     * The number of bits per entry is fixed when a list is created and can not be retrofitted, so a
     * status which does not fit is a permanent property of that list rather than a transient failure.
     *
     * @throws \Exception
     */
    public function testRefusesAStatusWhichDoesNotFitTheListsBits(): void
    {
        $this->givenList(1, '0,1');
        $this->givenAllocatedEntry();

        $this->expectException(UnsupportedStatusException::class);
        $this->expectExceptionMessage('Suspended');

        $this->sut()->setStatus(self::LIST_ID, 3, StatusTypeEnum::Suspended);
    }


    /**
     * A list records the statuses it was created allowing, so widening a pool later does not widen
     * lists which already exist.
     *
     * @throws \Exception
     */
    public function testRefusesAStatusTheListWasNotCreatedAllowing(): void
    {
        // Room for the value, but it was not among the statuses this list was created for.
        $this->givenList(2, '0,1');
        $this->givenAllocatedEntry();

        $this->expectException(UnsupportedStatusException::class);

        $this->sut()->setStatus(self::LIST_ID, 3, StatusTypeEnum::Suspended);
    }


    /**
     * @throws \Exception
     */
    public function testAllowsSuspensionOnAListCreatedForIt(): void
    {
        $this->givenList(2, '0,1,2');
        $this->givenAllocatedEntry();

        $this->assertTrue($this->sut()->setStatus(self::LIST_ID, 3, StatusTypeEnum::Suspended));
        $this->assertSame(StatusTypeEnum::Suspended->value, $this->sut()->getStatusValue(self::LIST_ID, 3));
    }


    /**
     * @throws \Exception
     */
    public function testCanReinstateARevokedEntry(): void
    {
        $this->givenList();
        $this->givenAllocatedEntry();

        $this->sut()->setStatus(self::LIST_ID, 3, StatusTypeEnum::Invalid);

        $this->assertTrue($this->sut()->setStatus(self::LIST_ID, 3, StatusTypeEnum::Valid));
        $this->assertSame(StatusTypeEnum::Valid->value, $this->sut()->getStatusValue(self::LIST_ID, 3));
    }


    /**
     * A change which lands between another caller's read and its write must stand, rather than being
     * silently overwritten by the value that caller had already decided on.
     *
     * @throws \Exception
     */
    public function testDoesNotOverwriteAChangeMadeSinceTheStatusWasRead(): void
    {
        $this->givenList();
        $this->givenAllocatedEntry();

        // Someone observed Valid; by the time they write, the entry has been revoked.
        $wasApplied = $this->statusListEntryRepository->updateStatus(
            self::LIST_ID,
            3,
            StatusTypeEnum::Invalid->value,
            StatusTypeEnum::Suspended->value,
        );

        $this->assertFalse($wasApplied);
        $this->assertSame(StatusTypeEnum::Valid->value, $this->sut()->getStatusValue(self::LIST_ID, 3));
    }


    /**
     * Losing one round of the compare-and-set is not a failure: the retry reads what actually got
     * there and applies the change on top, so the caller still ends up with what it asked for.
     *
     * @throws \Exception
     */
    public function testRetriesAgainstTheValueAnotherChangeLeftBehind(): void
    {
        $this->givenList();
        $this->givenAllocatedEntry();

        $entryRepositoryStub = new class (
            $this->createMock(ModuleConfig::class),
            $this->database,
            $this->createMock(ProtocolCache::class),
            new Helpers(),
        ) extends StatusListEntryRepository {
            public int $updateAttempts = 0;


            public function updateStatus(
                string $statusListId,
                int $idx,
                int $observedStatus,
                int $newStatus,
            ): bool {
                $this->updateAttempts++;

                // Stands in for another request changing the entry between this one's read and write.
                if ($this->updateAttempts === 1) {
                    parent::updateStatus($statusListId, $idx, $observedStatus, StatusTypeEnum::Suspended->value);

                    return false;
                }

                return parent::updateStatus($statusListId, $idx, $observedStatus, $newStatus);
            }
        };

        $updater = new DbStatusUpdater(
            $this->statusListRepository,
            $entryRepositoryStub,
            $this->loggerServiceMock,
        );

        $this->assertTrue($updater->setStatus(self::LIST_ID, 3, StatusTypeEnum::Invalid));
        $this->assertSame(2, $entryRepositoryStub->updateAttempts);
        $this->assertSame(StatusTypeEnum::Invalid->value, $this->sut()->getStatusValue(self::LIST_ID, 3));
    }


    /**
     * Losing every round has to be reported as a conflict rather than as the no-op that a false return
     * value means, since the entry ends up holding somebody else's value rather than the requested one.
     *
     * @throws \Exception
     */
    public function testRaisesAConflictWhenItKeepsLosingRatherThanReportingANoOp(): void
    {
        $this->givenList();
        $this->givenAllocatedEntry();

        $entryRepositoryStub = new class (
            $this->createMock(ModuleConfig::class),
            $this->database,
            $this->createMock(ProtocolCache::class),
            new Helpers(),
        ) extends StatusListEntryRepository {
            public function updateStatus(
                string $statusListId,
                int $idx,
                int $observedStatus,
                int $newStatus,
            ): bool {
                return false;
            }
        };

        $updater = new DbStatusUpdater(
            $this->statusListRepository,
            $entryRepositoryStub,
            $this->loggerServiceMock,
        );

        $this->expectException(StatusConflictException::class);

        $updater->setStatus(self::LIST_ID, 3, StatusTypeEnum::Invalid);
    }
}

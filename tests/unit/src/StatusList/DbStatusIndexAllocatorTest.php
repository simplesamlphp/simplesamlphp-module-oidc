<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use DateTimeImmutable;
use Exception;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\DbStatusIndexAllocator;
use SimpleSAML\Module\oidc\StatusList\StatusListKeyResolver;
use SimpleSAML\Module\oidc\StatusList\Values\StatusAllocation;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\TokenStatusList;

/**
 * Exercised against a real SQLite database rather than mocked repositories, because what is being
 * tested here is the behaviour of conditional updates and affected row counts. Mocking those away
 * would leave only the parts of the allocator which were never in doubt.
 */
#[CoversClass(DbStatusIndexAllocator::class)]
#[AllowMockObjectsWithoutExpectations]
class DbStatusIndexAllocatorTest extends TestCase
{
    protected const string POOL_ID = 'test-pool';

    protected const string CREDENTIAL_CONFIGURATION_ID = 'TestCredential';

    /** Small enough that a list can be filled by hand, and a multiple of 8 as a capacity must be. */
    protected const int CAPACITY = 8;


    protected Database $database;

    protected StatusListRepository $statusListRepository;

    protected StatusListEntryRepository $statusListEntryRepository;

    protected MockObject $keyResolverMock;

    protected MockObject $routesMock;

    protected MockObject $loggerServiceMock;

    protected string $signingKeyId = 'signing-key-1';


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

        // A shared in-memory database persists across tests, so each one starts from a clean slate.
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

        $this->keyResolverMock = $this->createMock(StatusListKeyResolver::class);
        $this->keyResolverMock->method('getCurrentKeyId')
            ->willReturnCallback(fn(): string => $this->signingKeyId);

        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('urlStatusList')
            ->willReturnCallback(
                static fn(string $id): string => 'https://op.example.org/module.php/oidc/statuslist/' . $id,
            );

        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }


    protected function sut(): DbStatusIndexAllocator
    {
        return new DbStatusIndexAllocator(
            $this->statusListRepository,
            $this->statusListEntryRepository,
            $this->keyResolverMock,
            new TokenStatusList(),
            $this->routesMock,
            new Helpers(),
            $this->loggerServiceMock,
        );
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function pool(int $capacity = self::CAPACITY): StatusListPool
    {
        return StatusListPool::fromConfig(
            self::POOL_ID,
            [
                StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => [self::CREDENTIAL_CONFIGURATION_ID],
                StatusListPool::KEY_CAPACITY => $capacity,
            ],
            StatusListKeyProfileEnum::DidJwk,
        );
    }


    /**
     * Allocates a credential which never expires, so the lists these tests work with are in the
     * non-expiring lane unless a test says otherwise.
     *
     * @throws \Exception
     */
    protected function allocate(string $credentialId): StatusAllocation
    {
        return $this->sut()->allocateFor(
            $this->pool(),
            $credentialId,
            self::CREDENTIAL_CONFIGURATION_ID,
            'subject-ref-hash',
            null,
        );
    }


    /**
     * @throws \Exception
     */
    protected function allocateExpiring(
        string $credentialId,
        string $expiresAt = '2027-08-07 12:00:00',
    ): StatusAllocation {
        return $this->sut()->allocateFor(
            $this->pool(),
            $credentialId,
            self::CREDENTIAL_CONFIGURATION_ID,
            'subject-ref-hash',
            new DateTimeImmutable($expiresAt),
        );
    }


    /**
     * The point of the whole arrangement: the two kinds of credential never share a list, so a list of
     * expiring credentials can always eventually be retired.
     *
     * @throws \Exception
     */
    public function testKeepsExpiringAndNonExpiringCredentialsInSeparateLists(): void
    {
        $expiring = $this->allocateExpiring('https://op.example.org/vc/expiring');
        $permanent = $this->allocate('https://op.example.org/vc/permanent');

        $this->assertNotSame($expiring->getStatusListId(), $permanent->getStatusListId());

        $this->assertSame(
            StatusListExpiryLaneEnum::Expiring,
            $this->statusListRepository->findByIdOnPrimary($expiring->getStatusListId())?->getExpiryLane(),
        );
        $this->assertSame(
            StatusListExpiryLaneEnum::NonExpiring,
            $this->statusListRepository->findByIdOnPrimary($permanent->getStatusListId())?->getExpiryLane(),
        );
    }


    /**
     * Two credentials of the same kind still share, or the lane would have bought a split herd for
     * nothing.
     *
     * @throws \Exception
     */
    public function testKeepsCredentialsOfTheSameKindTogether(): void
    {
        $first = $this->allocateExpiring('https://op.example.org/vc/first');
        $second = $this->allocateExpiring('https://op.example.org/vc/second');

        $this->assertSame($first->getStatusListId(), $second->getStatusListId());
    }


    /**
     * An open list in the other lane must never be selected. If it were, every probe against it would be
     * refused by the allocation guard, the allocator would read ten refusals as a full list, and it would
     * deactivate a perfectly good list belonging to the other lane.
     *
     * @throws \Exception
     */
    public function testDoesNotSelectAnOpenListFromTheOtherLane(): void
    {
        $permanent = $this->allocate('https://op.example.org/vc/permanent');
        $otherLaneListId = $permanent->getStatusListId();

        $expiring = $this->allocateExpiring('https://op.example.org/vc/expiring');

        $this->assertNotSame($otherLaneListId, $expiring->getStatusListId());

        // The other lane's list is untouched, and in particular still open.
        $this->assertTrue($this->statusListRepository->findByIdOnPrimary($otherLaneListId)?->isActive());
        $this->assertNull($this->statusListRepository->findByIdOnPrimary($otherLaneListId)?->getDeactivatedAt());
    }


    /**
     * A list being seeded in the other lane is not something this request may stand down for: it could
     * never allocate into it, so it would delete its own list and then find nothing to adopt.
     *
     * @throws \Exception
     */
    public function testDoesNotStandDownForAListBeingPreparedInTheOtherLane(): void
    {
        // Left inactive with no deactivation stamp, which is what a list still being seeded looks like,
        // and at a lower generation so it would win the stand-down comparison if the lane were ignored.
        $this->statusListRepository->create(
            'other-lane-being-seeded',
            'https://op.example.org/module.php/oidc/statuslist/other-lane-being-seeded',
            self::POOL_ID,
            $this->pool()->getPolicyFingerprint($this->signingKeyId),
            StatusListExpiryLaneEnum::NonExpiring,
            1,
            1,
            self::CAPACITY,
            '0,1',
            43200,
            604800,
            3600,
            $this->signingKeyId,
            StatusListKeyProfileEnum::DidJwk,
        );

        $allocation = $this->allocateExpiring('https://op.example.org/vc/expiring');

        $statusList = $this->statusListRepository->findByIdOnPrimary($allocation->getStatusListId());

        $this->assertNotSame('other-lane-being-seeded', $allocation->getStatusListId());
        $this->assertSame(StatusListExpiryLaneEnum::Expiring, $statusList?->getExpiryLane());
        $this->assertTrue($statusList?->isActive());
    }


    /**
     * Generations are counted within a pool, policy and lane, so the two lanes do not push each other's
     * numbering along and cannot collide on the unique constraint. A collision across lanes would be
     * unresolvable: the loser cannot adopt the winner's list, since its own lookups filter it out.
     *
     * @throws \Exception
     */
    public function testCountsGenerationsSeparatelyInEachLane(): void
    {
        $permanent = $this->allocate('https://op.example.org/vc/permanent');
        $expiring = $this->allocateExpiring('https://op.example.org/vc/expiring');

        $this->assertSame(
            1,
            $this->statusListRepository->findByIdOnPrimary($permanent->getStatusListId())?->getGeneration(),
        );
        $this->assertSame(
            1,
            $this->statusListRepository->findByIdOnPrimary($expiring->getStatusListId())?->getGeneration(),
        );
    }


    /**
     * @return array<array-key,mixed>
     */
    protected function statusListRows(): array
    {
        return $this->database->readPrimary(
            'SELECT * FROM ' . $this->database->applyPrefix('oidc_status_list') . ' ORDER BY generation',
        )->fetchAll();
    }


    /**
     * @throws \Exception
     */
    public function testCreatesSeedsAndActivatesAListOnTheFirstAllocation(): void
    {
        $allocation = $this->allocate('https://op.example.org/vc/abc');

        $rows = $this->statusListRows();
        $this->assertCount(1, $rows);

        $statusList = $this->statusListRepository->findByIdOnPrimary($allocation->getStatusListId());
        $this->assertNotNull($statusList);
        $this->assertTrue($statusList->isActive(), 'A seeded list must end up open for allocation.');
        $this->assertSame(1, $statusList->getGeneration());
        $this->assertSame(self::CAPACITY, $statusList->getCapacity());
        $this->assertSame($this->signingKeyId, $statusList->getSigningKeyId());
        $this->assertSame(StatusListKeyProfileEnum::DidJwk, $statusList->getKeyProfile());

        // Every index exists from the outset, which is what makes claiming one a conditional update.
        $seeded = $this->database->readPrimary(
            'SELECT COUNT(*) AS total FROM ' . $this->database->applyPrefix('oidc_status_list_entry') .
            ' WHERE status_list_id = :id',
            ['id' => $allocation->getStatusListId()],
        )->fetchAll();

        $this->assertSame(self::CAPACITY, (int)$seeded[0]['total']);
    }


    /**
     * The reference handed back is what goes into the credential, so it has to be the URI which was
     * stored, byte for byte, rather than one rebuilt later from the current base URL.
     *
     * @throws \Exception
     */
    public function testReturnsTheStoredUriAndAnInRangeIndex(): void
    {
        $allocation = $this->allocate('https://op.example.org/vc/abc');

        $statusList = $this->statusListRepository->findByIdOnPrimary($allocation->getStatusListId());

        $this->assertSame($statusList?->getUri(), $allocation->getUri());
        $this->assertSame($allocation->getUri(), $allocation->getStatusReference()->getUri());
        $this->assertGreaterThanOrEqual(0, $allocation->getIdx());
        $this->assertLessThan(self::CAPACITY, $allocation->getIdx());
    }


    /**
     * Claiming the index and recording what claimed it are one statement, so there is never a moment
     * where an index is taken but unattributable.
     *
     * @throws \Exception
     */
    public function testRecordsTheCredentialLinkageWithTheClaim(): void
    {
        $credentialId = 'https://op.example.org/vc/abc';
        $allocation = $this->allocate($credentialId);

        $entry = $this->statusListEntryRepository->findByListAndIdx(
            $allocation->getStatusListId(),
            $allocation->getIdx(),
        );

        $this->assertNotNull($entry);
        $this->assertTrue($entry->isAllocated());
        $this->assertSame($credentialId, $entry->getCredentialId());
        $this->assertSame(
            $this->statusListEntryRepository->hashCredentialId($credentialId),
            $entry->getCredentialIdHash(),
        );
        $this->assertSame(self::CREDENTIAL_CONFIGURATION_ID, $entry->getCredentialConfigurationId());
        $this->assertSame('subject-ref-hash', $entry->getSubjectRef());
        $this->assertSame(0, $entry->getStatus());
        // Null expiry marks a credential which never expires, which keeps its list from being retired.
        $this->assertNull($entry->getExpiresAt());
    }


    /**
     * @throws \Exception
     */
    public function testNeverHandsOutTheSameIndexTwice(): void
    {
        $seen = [];

        // Four is the load factor limit for this capacity, so this stays within one list.
        for ($i = 0; $i < 4; $i++) {
            $allocation = $this->allocate('https://op.example.org/vc/' . $i);
            $key = $allocation->getStatusListId() . '#' . $allocation->getIdx();

            $this->assertArrayNotHasKey($key, $seen, 'An index was handed out twice.');
            $seen[$key] = true;
        }

        $this->assertCount(4, $seen);
    }


    /**
     * A claim on an index someone else already took simply affects no rows. Nothing has to classify a
     * database error to discover that, which matters because this module can not do so reliably.
     *
     * @throws \Exception
     */
    public function testClaimingAnAlreadyTakenIndexAffectsNoRowsRatherThanRaising(): void
    {
        $allocation = $this->allocate('https://op.example.org/vc/first');

        $wasClaimed = $this->statusListEntryRepository->allocate(
            $allocation->getStatusListId(),
            $allocation->getIdx(),
            'https://op.example.org/vc/second',
            $this->statusListEntryRepository->hashCredentialId('https://op.example.org/vc/second'),
            self::CREDENTIAL_CONFIGURATION_ID,
            null,
            null,
        );

        $this->assertFalse($wasClaimed);

        // The first credential still holds it.
        $entry = $this->statusListEntryRepository->findByListAndIdx(
            $allocation->getStatusListId(),
            $allocation->getIdx(),
        );
        $this->assertSame('https://op.example.org/vc/first', $entry?->getCredentialId());
    }


    /**
     * A list which stopped accepting allocations must not take any more, even for an index which is
     * still free, otherwise a credential could land in a list already on its way to retirement.
     *
     * @throws \Exception
     */
    public function testWillNotClaimAnIndexInADeactivatedList(): void
    {
        $allocation = $this->allocate('https://op.example.org/vc/first');
        $statusListId = $allocation->getStatusListId();

        $this->assertTrue($this->statusListRepository->deactivate($statusListId));

        $freeIdx = ($allocation->getIdx() + 1) % self::CAPACITY;

        $wasClaimed = $this->statusListEntryRepository->allocate(
            $statusListId,
            $freeIdx,
            'https://op.example.org/vc/second',
            $this->statusListEntryRepository->hashCredentialId('https://op.example.org/vc/second'),
            self::CREDENTIAL_CONFIGURATION_ID,
            null,
            null,
        );

        $this->assertFalse($wasClaimed);
    }


    /**
     * Deactivating is what settles which of several workers goes on to create the successor.
     *
     * @throws \Exception
     */
    public function testOnlyOneCallerWinsDeactivation(): void
    {
        $allocation = $this->allocate('https://op.example.org/vc/first');

        $this->assertTrue($this->statusListRepository->deactivate($allocation->getStatusListId()));
        $this->assertFalse($this->statusListRepository->deactivate($allocation->getStatusListId()));
    }


    /**
     * Running out of picks must never surface as a failure to issue a credential. The list is closed, a
     * successor is started, and the credential is allocated there.
     *
     * @throws \Exception
     */
    public function testRunningOutOfPicksRotatesInsteadOfFailing(): void
    {
        $first = $this->allocate('https://op.example.org/vc/first');
        $firstListId = $first->getStatusListId();

        // Fill every remaining index directly, so the advisory counter stays low and the allocator
        // still considers this list worth trying. That is exactly the undercount the design tolerates.
        for ($idx = 0; $idx < self::CAPACITY; $idx++) {
            $this->statusListEntryRepository->allocate(
                $firstListId,
                $idx,
                'https://op.example.org/vc/filler-' . $idx,
                $this->statusListEntryRepository->hashCredentialId('filler-' . $idx),
                self::CREDENTIAL_CONFIGURATION_ID,
                null,
                null,
            );
        }

        $second = $this->allocate('https://op.example.org/vc/second');

        $this->assertNotSame($firstListId, $second->getStatusListId(), 'Allocation should have rotated.');

        $rows = $this->statusListRows();
        $this->assertCount(2, $rows);
        $this->assertSame(2, (int)$rows[1]['generation']);

        // The full list is closed rather than left to be picked again.
        $this->assertFalse($this->statusListRepository->findByIdOnPrimary($firstListId)?->isActive());
    }


    /**
     * The advisory counter is what triggers rotating early, before picks start colliding.
     *
     * @throws \Exception
     */
    public function testRotatesOnceTheLoadFactorIsReached(): void
    {
        $listIds = [];

        for ($i = 0; $i < 5; $i++) {
            $listIds[] = $this->allocate('https://op.example.org/vc/' . $i)->getStatusListId();
        }

        // Capacity 8 at a load factor of one half means the fifth allocation starts a second list.
        $this->assertCount(1, array_unique(array_slice($listIds, 0, 4)));
        $this->assertNotSame($listIds[3], $listIds[4]);
        $this->assertCount(2, $this->statusListRows());
    }


    /**
     * During a key rotation the issuer signs credentials with the current key. A list bound to the
     * previous one must stop being selected, or the profile saying the two are the same key breaks.
     *
     * @throws \Exception
     */
    public function testDoesNotAllocateIntoAListBoundToASupersededSigningKey(): void
    {
        $first = $this->allocate('https://op.example.org/vc/first');

        $this->signingKeyId = 'signing-key-2';

        $second = $this->allocate('https://op.example.org/vc/second');

        $this->assertNotSame($first->getStatusListId(), $second->getStatusListId());

        $newList = $this->statusListRepository->findByIdOnPrimary($second->getStatusListId());
        $this->assertSame('signing-key-2', $newList?->getSigningKeyId());

        // The superseded list stays open and served: credentials already point at it, and it is only
        // ineligible for new allocations, not retired.
        $this->assertTrue($this->statusListRepository->findByIdOnPrimary($first->getStatusListId())?->isActive());
    }


    /**
     * Changing a pool setting must likewise not leave lists created under the old policy eligible.
     *
     * @throws \Exception
     */
    public function testDoesNotAllocateIntoAListCreatedUnderADifferentPolicy(): void
    {
        $first = $this->allocate('https://op.example.org/vc/first');

        $widerPool = StatusListPool::fromConfig(
            self::POOL_ID,
            [
                StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => [self::CREDENTIAL_CONFIGURATION_ID],
                StatusListPool::KEY_CAPACITY => self::CAPACITY,
                StatusListPool::KEY_BITS => 2,
            ],
            StatusListKeyProfileEnum::DidJwk,
        );

        $second = $this->sut()->allocateFor(
            $widerPool,
            'https://op.example.org/vc/second',
            self::CREDENTIAL_CONFIGURATION_ID,
        );

        $this->assertNotSame($first->getStatusListId(), $second->getStatusListId());
        $this->assertSame(2, $this->statusListRepository->findByIdOnPrimary($second->getStatusListId())?->getBits());
    }


    /**
     * Successive lists in a pool take successive generations, which is what the unique constraint uses
     * to let exactly one of several workers create the successor.
     *
     * @throws \Exception
     */
    public function testASecondListForTheSamePoolAndGenerationCannotBeCreated(): void
    {
        $allocation = $this->allocate('https://op.example.org/vc/first');
        $existing = $this->statusListRepository->findByIdOnPrimary($allocation->getStatusListId());

        $this->expectException(Exception::class);

        $this->statusListRepository->create(
            'some-other-id',
            'https://op.example.org/module.php/oidc/statuslist/some-other-id',
            self::POOL_ID,
            (string)$existing?->getPolicyFingerprint(),
            StatusListExpiryLaneEnum::NonExpiring,
            (int)$existing?->getGeneration(),
            1,
            self::CAPACITY,
            '0,1',
            43200,
            604800,
            3600,
            $this->signingKeyId,
            StatusListKeyProfileEnum::DidJwk,
        );
    }


    /**
     * A list which was closed is not picked again; the next allocation starts the next generation.
     *
     * @throws \Exception
     */
    public function testStartsTheNextGenerationOnceTheOpenListIsClosed(): void
    {
        $first = $this->allocate('https://op.example.org/vc/first');

        $this->assertTrue($this->statusListRepository->deactivate($first->getStatusListId()));

        $second = $this->allocate('https://op.example.org/vc/second');

        $this->assertNotSame($first->getStatusListId(), $second->getStatusListId());
        $this->assertSame(
            2,
            $this->statusListRepository->findByIdOnPrimary($second->getStatusListId())?->getGeneration(),
        );
        $this->assertCount(2, $this->statusListRows());
    }


    /**
     * Losing the race to create a successor is recoverable without working out why the insert failed.
     *
     * The recovery is the same whatever the cause, which is the point: the database wrapper reports the
     * connection's error rather than the failing statement's and rethrows without the original, so a
     * unique constraint violation can not reliably be told apart from anything else. This stands in for
     * another worker having inserted the same generation between this request's read and its own write.
     *
     * @throws \Exception
     */
    public function testAdoptsAListAnotherRequestCreatedWhenItsOwnInsertFails(): void
    {
        // Seed a list which the racing worker is taken to have created and opened.
        $winner = $this->allocate('https://op.example.org/vc/winner');
        $winningListId = $winner->getStatusListId();

        $repositoryStub = new class (
            $this->createMock(ModuleConfig::class),
            $this->database,
            $this->createMock(ProtocolCache::class),
            new Helpers(),
        ) extends StatusListRepository {
            public bool $pretendNoListIsOpen = true;


            public function findActiveForPolicy(
                string $poolId,
                string $policyFingerprint,
                StatusListExpiryLaneEnum $expiryLane,
            ): array {
                // Empty on the first look, so the allocator decides a successor is needed. Populated
                // afterwards, which is what the racing worker's list becoming visible looks like.
                if ($this->pretendNoListIsOpen) {
                    $this->pretendNoListIsOpen = false;

                    return [];
                }

                return parent::findActiveForPolicy($poolId, $policyFingerprint, $expiryLane);
            }


            public function create(
                string $id,
                string $uri,
                string $poolId,
                string $policyFingerprint,
                StatusListExpiryLaneEnum $expiryLane,
                int $generation,
                int $bits,
                int $capacity,
                string $allowedStatuses,
                int $ttlSeconds,
                int $tokenValiditySeconds,
                int $refreshIntervalSeconds,
                string $signingKeyId,
                StatusListKeyProfileEnum $keyProfile,
            ): void {
                throw new Exception('Database error: duplicate generation.');
            }
        };

        $allocator = new DbStatusIndexAllocator(
            $repositoryStub,
            $this->statusListEntryRepository,
            $this->keyResolverMock,
            new TokenStatusList(),
            $this->routesMock,
            new Helpers(),
            $this->loggerServiceMock,
        );

        $allocation = $allocator->allocateFor(
            $this->pool(),
            'https://op.example.org/vc/loser',
            self::CREDENTIAL_CONFIGURATION_ID,
        );

        // The credential landed in the winner's list rather than the request failing.
        $this->assertSame($winningListId, $allocation->getStatusListId());
        $this->assertCount(1, $this->statusListRows());
    }


    /**
     * A request arriving while another is still seeding a list must join that list rather than start a
     * second one. Privacy comes from many credentials sharing a list, so splitting a pool across
     * sparse lists is a real cost, not just wasted work.
     *
     * @throws \Exception
     */
    public function testJoinsAListAnotherRequestIsStillSeedingRatherThanStartingASecondOne(): void
    {
        // A list which exists, has its entries, but was never opened is what a seed in progress looks
        // like from another request's point of view.
        $this->statusListRepository->create(
            'being-seeded',
            'https://op.example.org/module.php/oidc/statuslist/being-seeded',
            self::POOL_ID,
            $this->pool()->getPolicyFingerprint($this->signingKeyId),
            StatusListExpiryLaneEnum::NonExpiring,
            1,
            1,
            self::CAPACITY,
            '0,1',
            43200,
            604800,
            3600,
            $this->signingKeyId,
            StatusListKeyProfileEnum::DidJwk,
        );
        $this->statusListEntryRepository->seed('being-seeded', self::CAPACITY);

        $repositoryStub = new class (
            $this->createMock(ModuleConfig::class),
            $this->database,
            $this->createMock(ProtocolCache::class),
            new Helpers(),
        ) extends StatusListRepository {
            public int $activeLookups = 0;


            public function findActiveForPolicy(
                string $poolId,
                string $policyFingerprint,
                StatusListExpiryLaneEnum $expiryLane,
            ): array {
                $this->activeLookups++;

                // Stands in for the other request finishing its seed while this one is waiting: the
                // first look finds nothing open, the next finds the list it was waiting for.
                if ($this->activeLookups === 2) {
                    $this->activate('being-seeded');
                }

                return parent::findActiveForPolicy($poolId, $policyFingerprint, $expiryLane);
            }
        };

        $allocator = new DbStatusIndexAllocator(
            $repositoryStub,
            $this->statusListEntryRepository,
            $this->keyResolverMock,
            new TokenStatusList(),
            $this->routesMock,
            new Helpers(),
            $this->loggerServiceMock,
        );

        $allocation = $allocator->allocateFor(
            $this->pool(),
            'https://op.example.org/vc/second',
            self::CREDENTIAL_CONFIGURATION_ID,
        );

        $this->assertSame('being-seeded', $allocation->getStatusListId());
        $this->assertGreaterThanOrEqual(2, $repositoryStub->activeLookups, 'The wait path was not taken.');
        $this->assertCount(1, $this->statusListRows(), 'A second list should not have been started.');
    }


    /**
     * A list left unopened by a request which died mid-seed must not stall every later request. Past
     * its staleness window it is ignored and a fresh list is started, so issuance still succeeds.
     *
     * @throws \Exception
     */
    public function testIgnoresAnAbandonedHalfSeededListInsteadOfWaitingForever(): void
    {
        $this->statusListRepository->create(
            'abandoned',
            'https://op.example.org/module.php/oidc/statuslist/abandoned',
            self::POOL_ID,
            $this->pool()->getPolicyFingerprint($this->signingKeyId),
            StatusListExpiryLaneEnum::NonExpiring,
            1,
            1,
            self::CAPACITY,
            '0,1',
            43200,
            604800,
            3600,
            $this->signingKeyId,
            StatusListKeyProfileEnum::DidJwk,
        );

        // Backdate it well past the window in which a seed could still be running.
        $this->database->write(
            'UPDATE ' . $this->database->applyPrefix('oidc_status_list') .
            " SET created_at = '2020-01-01 00:00:00' WHERE id = 'abandoned'",
        );

        $started = microtime(true);
        $allocation = $this->allocate('https://op.example.org/vc/first');
        $elapsed = microtime(true) - $started;

        $this->assertNotSame('abandoned', $allocation->getStatusListId());
        $this->assertLessThan(1.0, $elapsed, 'An abandoned list must not be waited on.');

        // The abandoned list keeps its generation, so the new one takes the next.
        $this->assertSame(
            2,
            $this->statusListRepository->findByIdOnPrimary($allocation->getStatusListId())?->getGeneration(),
        );
    }


    /**
     * The unique constraint on (pool_id, generation) only settles a race between requests which picked
     * the same generation. Two requests reading the highest generation a moment apart pick different
     * ones, so both inserts succeed and nothing collides. Whoever holds the higher generation has to
     * notice and stand down, or the pool ends up with two half empty lists and half the herd each.
     *
     * @throws \Exception
     */
    public function testStandsDownWhenAnotherRequestIsPreparingAnEarlierGeneration(): void
    {
        $fingerprint = $this->pool()->getPolicyFingerprint($this->signingKeyId);

        // The other request got in first and is still seeding its generation 1.
        $this->statusListRepository->create(
            'earlier-generation',
            'https://op.example.org/module.php/oidc/statuslist/earlier-generation',
            self::POOL_ID,
            $fingerprint,
            StatusListExpiryLaneEnum::NonExpiring,
            1,
            1,
            self::CAPACITY,
            '0,1',
            43200,
            604800,
            3600,
            $this->signingKeyId,
            StatusListKeyProfileEnum::DidJwk,
        );
        $this->statusListEntryRepository->seed('earlier-generation', self::CAPACITY);

        $repositoryStub = new class (
            $this->createMock(ModuleConfig::class),
            $this->database,
            $this->createMock(ProtocolCache::class),
            new Helpers(),
        ) extends StatusListRepository {
            public int $activeLookups = 0;


            public function findBeingPreparedForPolicy(
                string $poolId,
                string $policyFingerprint,
                StatusListExpiryLaneEnum $expiryLane,
                DateTimeImmutable $createdAfter,
                ?int $belowGeneration = null,
            ): array {
                // Hide the in-progress list from the pre-creation check only, so this request goes
                // ahead and creates its own generation 2 -- which is exactly the interleaving where the
                // unique constraint does not fire. The post-creation check still sees it.
                if ($belowGeneration === null) {
                    return [];
                }

                return parent::findBeingPreparedForPolicy(
                    $poolId,
                    $policyFingerprint,
                    $expiryLane,
                    $createdAfter,
                    $belowGeneration,
                );
            }


            public function findActiveForPolicy(
                string $poolId,
                string $policyFingerprint,
                StatusListExpiryLaneEnum $expiryLane,
            ): array {
                $this->activeLookups++;

                // The other request finishes its seed while this one is standing down.
                if ($this->activeLookups >= 3) {
                    $this->activate('earlier-generation');
                }

                return parent::findActiveForPolicy($poolId, $policyFingerprint, $expiryLane);
            }
        };

        $allocator = new DbStatusIndexAllocator(
            $repositoryStub,
            $this->statusListEntryRepository,
            $this->keyResolverMock,
            new TokenStatusList(),
            $this->routesMock,
            new Helpers(),
            $this->loggerServiceMock,
        );

        $allocation = $allocator->allocateFor(
            $this->pool(),
            'https://op.example.org/vc/second',
            self::CREDENTIAL_CONFIGURATION_ID,
        );

        $this->assertSame('earlier-generation', $allocation->getStatusListId());

        // The redundant generation 2 was removed rather than left behind half seeded.
        $this->assertCount(1, $this->statusListRows());
    }


    /**
     * Standing down must never leave the redundant list behind, and it must only ever remove one which
     * was never opened, so that a list a credential could point at is untouchable.
     *
     * @throws \Exception
     */
    public function testOnlyRemovesAListWhichWasNeverOpened(): void
    {
        $allocation = $this->allocate('https://op.example.org/vc/first');

        $this->assertFalse(
            $this->statusListRepository->deleteUnopened($allocation->getStatusListId()),
            'An open list must not be removable.',
        );
        $this->assertNotNull($this->statusListRepository->findByIdOnPrimary($allocation->getStatusListId()));

        $this->statusListRepository->create(
            'never-opened',
            'https://op.example.org/module.php/oidc/statuslist/never-opened',
            self::POOL_ID,
            'some-fingerprint',
            StatusListExpiryLaneEnum::NonExpiring,
            99,
            1,
            self::CAPACITY,
            '0,1',
            43200,
            604800,
            3600,
            $this->signingKeyId,
            StatusListKeyProfileEnum::DidJwk,
        );

        $this->assertTrue($this->statusListRepository->deleteUnopened('never-opened'));
        $this->assertNull($this->statusListRepository->findByIdOnPrimary('never-opened'));
    }


    /**
     * A request which died after creating a list but before opening it must not take the pool down
     * with it. Standing down repeatedly for a list nobody is finishing would fail every issuance until
     * the abandoned row aged out, so the next request takes over instead.
     *
     * @throws \Exception
     */
    public function testTakesOverWhenTheListItStoodDownForIsNeverOpened(): void
    {
        // Created moments ago and never opened, and its creator is gone, so nothing will ever open it.
        $this->statusListRepository->create(
            'never-finished',
            'https://op.example.org/module.php/oidc/statuslist/never-finished',
            self::POOL_ID,
            $this->pool()->getPolicyFingerprint($this->signingKeyId),
            StatusListExpiryLaneEnum::NonExpiring,
            1,
            1,
            self::CAPACITY,
            '0,1',
            43200,
            604800,
            3600,
            $this->signingKeyId,
            StatusListKeyProfileEnum::DidJwk,
        );

        $started = microtime(true);
        $allocation = $this->allocate('https://op.example.org/vc/first');
        $elapsed = microtime(true) - $started;

        // Issuance succeeded rather than failing while the abandoned row was still recent.
        $this->assertNotSame('never-finished', $allocation->getStatusListId());
        $this->assertTrue(
            $this->statusListRepository->findByIdOnPrimary($allocation->getStatusListId())?->isActive(),
        );

        // One wait, not one per creation attempt until the budget ran out.
        $this->assertLessThan(8.0, $elapsed);
    }


    /**
     * A list which has reached the point where a successor is started must be closed, not merely
     * skipped. Left open it would come back in every candidate query for ever, and retirement waits on
     * the moment it was closed.
     *
     * @throws \Exception
     */
    public function testClosesAListOnceItIsFullRatherThanLeavingItOpen(): void
    {
        $firstListId = null;

        for ($i = 0; $i < 5; $i++) {
            $allocation = $this->allocate('https://op.example.org/vc/' . $i);
            $firstListId ??= $allocation->getStatusListId();
        }

        $first = $this->statusListRepository->findByIdOnPrimary((string)$firstListId);

        $this->assertFalse($first?->isActive(), 'A full list must not be left open.');
        $this->assertNotNull($first?->getDeactivatedAt(), 'Retirement needs to know when it was closed.');

        // And it is gone from the candidate set, so later allocations do not keep re-reading it.
        $this->assertNotContains(
            $firstListId,
            array_map(
                static fn($record): string => $record->getId(),
                $this->statusListRepository->findActiveForPolicy(
                    self::POOL_ID,
                    $this->pool()->getPolicyFingerprint($this->signingKeyId),
                    StatusListExpiryLaneEnum::NonExpiring,
                ),
            ),
        );
    }


    /**
     * The allocation counter is advisory and may undercount, so failing to bump it must not undo an
     * index which is already durably claimed. Throwing here would consume the slot and then fail the
     * credential, and retrying it would collide on its unique hash.
     *
     * @throws \Exception
     */
    public function testStillReturnsTheAllocationWhenTheAdvisoryCounterCannotBeUpdated(): void
    {
        $repositoryStub = new class (
            $this->createMock(ModuleConfig::class),
            $this->database,
            $this->createMock(ProtocolCache::class),
            new Helpers(),
        ) extends StatusListRepository {
            public function incrementAllocatedCount(string $id): void
            {
                throw new Exception('Database error: deadlock found.');
            }
        };

        $allocator = new DbStatusIndexAllocator(
            $repositoryStub,
            $this->statusListEntryRepository,
            $this->keyResolverMock,
            new TokenStatusList(),
            $this->routesMock,
            new Helpers(),
            $this->loggerServiceMock,
        );

        $allocation = $allocator->allocateFor(
            $this->pool(),
            'https://op.example.org/vc/counter',
            self::CREDENTIAL_CONFIGURATION_ID,
        );

        $entry = $this->statusListEntryRepository->findByListAndIdx(
            $allocation->getStatusListId(),
            $allocation->getIdx(),
        );

        $this->assertTrue($entry?->isAllocated());
        $this->assertSame('https://op.example.org/vc/counter', $entry?->getCredentialId());
    }


    /**
     * The most common way to lose the race is on a cold start, where the winner is still seeding at the
     * moment the loser's insert fails -- that is *why* it failed. Giving up on the winner at that point
     * and starting the next generation would give the pool two half empty lists and each of them half
     * the herd, so the loser waits for the winner to open instead.
     *
     * @throws \Exception
     */
    public function testWaitsForAWinnerWhichIsStillSeedingWhenItsOwnInsertFails(): void
    {
        $fingerprint = $this->pool()->getPolicyFingerprint($this->signingKeyId);

        // The winner's list: inserted, entries written, not yet opened.
        $this->statusListRepository->create(
            'winner',
            'https://op.example.org/module.php/oidc/statuslist/winner',
            self::POOL_ID,
            $fingerprint,
            StatusListExpiryLaneEnum::NonExpiring,
            1,
            1,
            self::CAPACITY,
            '0,1',
            43200,
            604800,
            3600,
            $this->signingKeyId,
            StatusListKeyProfileEnum::DidJwk,
        );
        $this->statusListEntryRepository->seed('winner', self::CAPACITY);

        $repositoryStub = new class (
            $this->createMock(ModuleConfig::class),
            $this->database,
            $this->createMock(ProtocolCache::class),
            new Helpers(),
        ) extends StatusListRepository {
            public int $activeLookups = 0;


            public function findBeingPreparedForPolicy(
                string $poolId,
                string $policyFingerprint,
                StatusListExpiryLaneEnum $expiryLane,
                DateTimeImmutable $createdAfter,
                ?int $belowGeneration = null,
            ): array {
                // Hidden from the check before creating, so this request goes ahead and tries to insert
                // the same generation the winner already took.
                if ($belowGeneration === null && $this->activeLookups < 1) {
                    return [];
                }

                return parent::findBeingPreparedForPolicy(
                    $poolId,
                    $policyFingerprint,
                    $expiryLane,
                    $createdAfter,
                    $belowGeneration,
                );
            }


            public function findActiveForPolicy(
                string $poolId,
                string $policyFingerprint,
                StatusListExpiryLaneEnum $expiryLane,
            ): array {
                $this->activeLookups++;

                // The winner finishes seeding partway through this request's wait.
                if ($this->activeLookups >= 3) {
                    $this->activate('winner');
                }

                return parent::findActiveForPolicy($poolId, $policyFingerprint, $expiryLane);
            }


            public function create(
                string $id,
                string $uri,
                string $poolId,
                string $policyFingerprint,
                StatusListExpiryLaneEnum $expiryLane,
                int $generation,
                int $bits,
                int $capacity,
                string $allowedStatuses,
                int $ttlSeconds,
                int $tokenValiditySeconds,
                int $refreshIntervalSeconds,
                string $signingKeyId,
                StatusListKeyProfileEnum $keyProfile,
            ): void {
                throw new Exception('Database error: duplicate generation.');
            }
        };

        $allocator = new DbStatusIndexAllocator(
            $repositoryStub,
            $this->statusListEntryRepository,
            $this->keyResolverMock,
            new TokenStatusList(),
            $this->routesMock,
            new Helpers(),
            $this->loggerServiceMock,
        );

        $allocation = $allocator->allocateFor(
            $this->pool(),
            'https://op.example.org/vc/loser',
            self::CREDENTIAL_CONFIGURATION_ID,
        );

        $this->assertSame('winner', $allocation->getStatusListId());
        $this->assertCount(1, $this->statusListRows(), 'The pool should have converged on one list.');
    }


    /**
     * When the insert fails and there is genuinely no other list, there is nothing to fall back to.
     *
     * @throws \Exception
     */
    public function testRaisesWhenItsInsertFailsAndNoOtherListExists(): void
    {
        $repositoryStub = new class (
            $this->createMock(ModuleConfig::class),
            $this->database,
            $this->createMock(ProtocolCache::class),
            new Helpers(),
        ) extends StatusListRepository {
            public function create(
                string $id,
                string $uri,
                string $poolId,
                string $policyFingerprint,
                StatusListExpiryLaneEnum $expiryLane,
                int $generation,
                int $bits,
                int $capacity,
                string $allowedStatuses,
                int $ttlSeconds,
                int $tokenValiditySeconds,
                int $refreshIntervalSeconds,
                string $signingKeyId,
                StatusListKeyProfileEnum $keyProfile,
            ): void {
                throw new Exception('Database error: disk full.');
            }
        };

        $allocator = new DbStatusIndexAllocator(
            $repositoryStub,
            $this->statusListEntryRepository,
            $this->keyResolverMock,
            new TokenStatusList(),
            $this->routesMock,
            new Helpers(),
            $this->loggerServiceMock,
        );

        $this->expectException(StatusListException::class);

        $allocator->allocateFor(
            $this->pool(),
            'https://op.example.org/vc/x',
            self::CREDENTIAL_CONFIGURATION_ID,
        );
    }


    /**
     * @throws \Exception
     */
    public function testCountsAllocationsForTheAdvisoryCounter(): void
    {
        $allocation = $this->allocate('https://op.example.org/vc/first');

        $this->assertSame(
            1,
            $this->statusListRepository->findByIdOnPrimary($allocation->getStatusListId())?->getAllocatedCount(),
        );
        $this->assertSame(1, $this->statusListEntryRepository->countAllocated($allocation->getStatusListId()));
    }


    /**
     * Only a failure to obtain any list at all is an error.
     *
     * @throws \Exception
     */
    public function testRaisesWhenNoListCanBeObtained(): void
    {
        $keyResolverMock = $this->createMock(StatusListKeyResolver::class);
        $keyResolverMock->method('getCurrentKeyId')
            ->willThrowException(new StatusListException('No signing key.'));

        $allocator = new DbStatusIndexAllocator(
            $this->statusListRepository,
            $this->statusListEntryRepository,
            $keyResolverMock,
            new TokenStatusList(),
            $this->routesMock,
            new Helpers(),
            $this->loggerServiceMock,
        );

        $this->expectException(StatusListException::class);

        $allocator->allocateFor($this->pool(), 'https://op.example.org/vc/x', self::CREDENTIAL_CONFIGURATION_ID);
    }
}

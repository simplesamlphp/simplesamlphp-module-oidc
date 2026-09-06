<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateTimeImmutable;
use DateTimeZone;
use PDOStatement;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
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
use SimpleSAML\Module\oidc\StatusList\Values\StatusListAllocationTarget;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListReconciliationCandidate;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

/**
 * Storage for Status Lists themselves: the whole of a list's life, from the moment a request is still
 * preparing one through to the moment its entries are purged.
 *
 * Everything here runs against a real SQLite database with the real migrations applied, because most of
 * what this class does is expressed in SQL rather than in PHP. A guard written into a WHERE clause is
 * not observable through a mocked connection at all -- the compare-and-set which publishes a token, the
 * conditions which decide whether a list may be deleted or retired, the cursor which pages past rows
 * which left the result set -- so a mocked one would only ever confirm which statement was sent.
 *
 * Two tests are the exception and mock the connection deliberately, and they are the two about which
 * connection is read. This database has no secondary, so `read()` and `readPrimary()` reach the same
 * rows, and a repository which had lost the distinction entirely would return exactly what one which
 * kept it returns.
 */
#[CoversClass(StatusListRepository::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusListRepositoryTest extends TestCase
{
    protected const string LIST_ID = 'a-status-list-id';

    protected const string OTHER_LIST_ID = 'another-status-list-id';

    protected const string POOL_ID = 'default';

    protected const string POLICY = 'a-policy-fingerprint';

    protected const int CAPACITY = 8;


    protected MockObject $moduleConfigMock;

    protected Helpers $helpers;

    protected StatusListRepository $repository;

    protected StatusListEntryRepository $entryRepository;


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


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->helpers = new Helpers();

        $this->repository = new StatusListRepository(
            $this->moduleConfigMock,
            Database::getInstance(),
            null,
            $this->helpers,
        );

        $this->entryRepository = new StatusListEntryRepository(
            $this->moduleConfigMock,
            Database::getInstance(),
            null,
            $this->helpers,
        );

        Database::getInstance()->write(sprintf('DELETE FROM %s', $this->entryRepository->getTableName()));
        Database::getInstance()->write(sprintf('DELETE FROM %s', $this->repository->getTableName()));
    }


    /**
     * @throws \Exception
     */
    protected function createList(
        string $id = self::LIST_ID,
        int $generation = 1,
        string $poolId = self::POOL_ID,
        string $policyFingerprint = self::POLICY,
        StatusListExpiryLaneEnum $expiryLane = StatusListExpiryLaneEnum::Expiring,
        StatusListKeyProfileEnum $keyProfile = StatusListKeyProfileEnum::DidJwk,
        ?string $issuerIdentifier = null,
        bool $activate = true,
        int $bits = 1,
    ): void {
        $this->repository->create(
            $id,
            'https://op.example.org/statuslist/' . $id,
            $poolId,
            $policyFingerprint,
            $expiryLane,
            $generation,
            $bits,
            self::CAPACITY,
            implode(',', [StatusTypeEnum::Valid->value, StatusTypeEnum::Invalid->value]),
            43200,
            604800,
            3600,
            'a-signing-key-id',
            $keyProfile,
            $issuerIdentifier,
        );

        if ($activate) {
            $this->repository->activate($id);
        }
    }


    /**
     * Round trips the column the did:web key profile rests on. The identifier is written when the list
     * is created and read back with the row, so signing never has to ask configuration who the issuer
     * was -- which is what keeps a changed setting from rewriting the issuer of tokens already being
     * verified. The other profiles derive their identity and leave it null.
     *
     * @throws \Exception
     */
    public function testRecordsTheIssuerIdentifierAListWasCreatedUnder(): void
    {
        $this->createList();
        $this->createList(
            id: 'a-did-web-list',
            generation: 2,
            keyProfile: StatusListKeyProfileEnum::DidWeb,
            issuerIdentifier: 'did:web:issuer.example.org',
        );

        $this->assertNull($this->repository->findById(self::LIST_ID)?->getIssuerIdentifier());

        $record = $this->repository->findById('a-did-web-list');

        $this->assertSame(StatusListKeyProfileEnum::DidWeb, $record?->getKeyProfile());
        $this->assertSame('did:web:issuer.example.org', $record->getIssuerIdentifier());
    }


    /**
     * Which DID documents still have to resolve. Lists sharing an identifier ask for one document
     * between them, and a list on another key profile asks for none, so both collapse away. The
     * retired one is the case which matters: it answers 404, so nothing resolves its issuer any more
     * and an operator is free to stop publishing it -- which is only true while nothing else names it.
     *
     * @throws \Exception
     */
    public function testReportsTheIssuerIdentifiersOfListsWhichAreStillServed(): void
    {
        $this->createList();
        $this->createList(
            id: 'first-under-one',
            generation: 2,
            keyProfile: StatusListKeyProfileEnum::DidWeb,
            issuerIdentifier: 'did:web:one.example.org',
        );
        $this->createList(
            id: 'second-under-one',
            generation: 3,
            keyProfile: StatusListKeyProfileEnum::DidWeb,
            issuerIdentifier: 'did:web:one.example.org',
        );
        $this->createList(
            id: 'only-under-two',
            generation: 4,
            keyProfile: StatusListKeyProfileEnum::DidWeb,
            issuerIdentifier: 'did:web:two.example.org',
        );

        $this->assertSame(
            ['did:web:one.example.org', 'did:web:two.example.org'],
            $this->repository->getUnretiredIssuerIdentifiers(),
        );

        // Deactivation is not retirement. A deactivated list has stopped taking new credentials but
        // is still served to the ones it already holds, so its document is still required.
        $this->repository->deactivate('only-under-two');

        $this->assertSame(
            ['did:web:one.example.org', 'did:web:two.example.org'],
            $this->repository->getUnretiredIssuerIdentifiers(),
        );

        $this->assertTrue($this->repository->retire('only-under-two', $this->spentBefore()));

        $this->assertSame(
            ['did:web:one.example.org'],
            $this->repository->getUnretiredIssuerIdentifiers(),
        );
    }


    /**
     * Two identifiers differing only in case are two identifiers: a `did:web` carries path segments,
     * and those are case sensitive. MySQL's usual collation is not, so leaving the deduplication to
     * `SELECT DISTINCT` would fold these into one arbitrarily chosen row -- and the one dropped is an
     * identity whose document is still required, reported to nobody.
     *
     * This runs on SQLite, which compares TEXT byte for byte and so would pass either way. It pins the
     * contract rather than reproducing the collation, which is also why the deduplication is in PHP:
     * there is no test here which could have caught it in SQL.
     *
     * @throws \Exception
     */
    public function testKeepsIssuerIdentifiersWhichDifferOnlyInCaseApart(): void
    {
        $this->createList(
            id: 'lower',
            keyProfile: StatusListKeyProfileEnum::DidWeb,
            issuerIdentifier: 'did:web:example.org:issuers:alice',
        );
        $this->createList(
            id: 'upper',
            generation: 2,
            keyProfile: StatusListKeyProfileEnum::DidWeb,
            issuerIdentifier: 'did:web:example.org:issuers:Alice',
        );

        // Byte order, not the database's, which is the other half of the same promise: the display
        // must not reshuffle because a deployment moved to another collation.
        $this->assertSame(
            ['did:web:example.org:issuers:Alice', 'did:web:example.org:issuers:alice'],
            $this->repository->getUnretiredIssuerIdentifiers(),
        );
    }


    /**
     * Deactivation is stamped with the moment it happened, which is now, and the retirement candidate
     * query looks for lists deactivated before a cut-off. Backdating the column is how a test says a
     * list has been sitting deactivated for a while.
     *
     * @throws \Exception
     */
    protected function backdateDeactivation(string $id, string $deactivatedAt): void
    {
        Database::getInstance()->write(
            sprintf('UPDATE %s SET deactivated_at = :deactivated_at WHERE id = :id', $this->repository->getTableName()),
            [
                'deactivated_at' => $deactivatedAt,
                'id' => $id,
            ],
        );
    }


    /**
     * A moment far enough ahead that any expiry a test sets is behind it, for the cases which are not
     * about the expiry guard itself.
     */
    protected function spentBefore(): DateTimeImmutable
    {
        return new DateTimeImmutable('2099-01-01 00:00:00');
    }


    /**
     * One combination the current configuration would allocate into.
     */
    protected function target(
        string $policyFingerprint = self::POLICY,
        StatusListExpiryLaneEnum $expiryLane = StatusListExpiryLaneEnum::Expiring,
        string $poolId = self::POOL_ID,
    ): StatusListAllocationTarget {
        return new StatusListAllocationTarget($poolId, $policyFingerprint, $expiryLane);
    }


    /**
     * A pool which has stopped using one of the two lanes leaves its list in the other one active and
     * reachable by nothing: the policy fingerprint does not change when a credential configuration gains
     * or loses a lifetime, so a comparison of pool and policy alone would keep that list for ever, still
     * served, never retired. Removing the last credential lifetime from a pool is the ordinary way to
     * arrive here, and it is the transition this whole arrangement is most likely to prompt.
     *
     * @throws \Exception
     */
    public function testDeactivatesListsInALaneThePoolNoLongerAllocatesInto(): void
    {
        $this->createList(self::LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::Expiring);

        $this->assertSame(
            1,
            $this->repository->deactivateSuperseded(
                [$this->target(self::POLICY, StatusListExpiryLaneEnum::NonExpiring)],
            ),
        );

        $statusList = $this->repository->findByIdOnPrimary(self::LIST_ID);

        $this->assertFalse($statusList?->isActive());
        $this->assertInstanceOf(DateTimeImmutable::class, $statusList?->getDeactivatedAt());
    }


    /**
     * The same transition the other way round, which is what giving a pool's last configuration a
     * lifetime looks like.
     *
     * @throws \Exception
     */
    public function testDeactivatesANonExpiringListOnceThePoolOnlyIssuesExpiringCredentials(): void
    {
        $this->createList(self::LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::NonExpiring);

        $this->assertSame(
            1,
            $this->repository->deactivateSuperseded(
                [$this->target(self::POLICY, StatusListExpiryLaneEnum::Expiring)],
            ),
        );

        $this->assertFalse($this->repository->findByIdOnPrimary(self::LIST_ID)?->isActive());
    }


    /**
     * The whole point, end to end: two lists of one pool, one per lane, each holding the kind of
     * credential its lane is for. Both have stopped accepting allocations and both have waited out the
     * grace, and only the expiring one is retired -- so its entry rows become recoverable while the
     * other goes on being served, which is what a credential that never expires requires.
     *
     * @throws \Exception
     */
    public function testRetiresTheExpiringListAndKeepsTheNonExpiringOne(): void
    {
        $this->createList(self::LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::Expiring);
        $this->createList(self::OTHER_LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::NonExpiring);

        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->entryRepository->seed(self::OTHER_LIST_ID, self::CAPACITY);

        // Each list takes only the kind of credential its lane accepts; the guard inside allocate()
        // refuses the other, so this arrangement is the only one reachable.
        $this->assertTrue($this->entryRepository->allocate(
            self::LIST_ID,
            0,
            'urn:vc:expiring',
            $this->entryRepository->hashCredentialId('urn:vc:expiring'),
            'UniversityDegree',
            null,
            new DateTimeImmutable('2026-06-01 09:00:00'),
        ));
        $this->assertTrue($this->entryRepository->allocate(
            self::OTHER_LIST_ID,
            0,
            'urn:vc:permanent',
            $this->entryRepository->hashCredentialId('urn:vc:permanent'),
            'UniversityDegree',
            null,
            null,
        ));

        // Both stop accepting allocations, and both have been sitting that way long enough to be looked
        // at. Without the backdating neither is a candidate at all, and the negative assertion below
        // would only be saying that an active list does not retire.
        foreach ([self::LIST_ID, self::OTHER_LIST_ID] as $id) {
            $this->repository->deactivate($id);
            $this->backdateDeactivation($id, '2026-01-01 09:00:00');
        }

        $now = new DateTimeImmutable('2026-08-07 12:00:00');

        $this->assertSame([self::LIST_ID], $this->repository->findRetirementCandidates($now, 10));
        $this->assertTrue($this->repository->retire(self::LIST_ID, $now));
        $this->assertFalse($this->repository->retire(self::OTHER_LIST_ID, $now));

        $this->assertTrue($this->repository->findByIdOnPrimary(self::LIST_ID)?->isRetired());
        $this->assertFalse($this->repository->findByIdOnPrimary(self::OTHER_LIST_ID)?->isRetired());
    }


    /**
     * The other half of the same rule, and the one which would turn a mixed pool into a rotation loop if
     * it were got wrong: while a pool allocates into both lanes, both of its lists are current and
     * neither may be deactivated. Deactivating one every run would have the allocator recreate it every
     * run, at a hundred and thirty thousand entry rows a time.
     *
     * @throws \Exception
     */
    public function testLeavesBothLanesOfAMixedPoolActive(): void
    {
        $this->createList(self::LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::Expiring);
        $this->createList(self::OTHER_LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::NonExpiring);

        $this->assertSame(
            0,
            $this->repository->deactivateSuperseded([
                $this->target(self::POLICY, StatusListExpiryLaneEnum::Expiring),
                $this->target(self::POLICY, StatusListExpiryLaneEnum::NonExpiring),
            ]),
        );

        $this->assertTrue($this->repository->findByIdOnPrimary(self::LIST_ID)?->isActive());
        $this->assertTrue($this->repository->findByIdOnPrimary(self::OTHER_LIST_ID)?->isActive());
    }


    /**
     * Both lanes of one pool and policy can hold the same generation, since that is the scope the
     * uniqueness is declared over. Two lists sharing a generation across lanes is normal, not a clash.
     *
     * @throws \Exception
     */
    public function testAllowsTheSameGenerationInEachLane(): void
    {
        $this->createList(self::LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::Expiring);
        $this->createList(self::OTHER_LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::NonExpiring);

        $this->assertSame(
            1,
            $this->repository->getHighestGeneration(
                self::POOL_ID,
                self::POLICY,
                StatusListExpiryLaneEnum::Expiring,
            ),
        );
        $this->assertSame(
            1,
            $this->repository->getHighestGeneration(
                self::POOL_ID,
                self::POLICY,
                StatusListExpiryLaneEnum::NonExpiring,
            ),
        );
    }


    /**
     * The counter is read over the same scope the unique constraint covers, so a list under a different
     * policy -- during a signing key rotation, say -- does not raise the generation a request in this
     * one will pick. Anything wider would have two requests which cannot use each other's lists collide,
     * and the loser would spend one of its bounded creation attempts finding nothing to adopt.
     *
     * @throws \Exception
     */
    public function testCountsGenerationsSeparatelyForEachPolicy(): void
    {
        $this->createList(self::LIST_ID, 7, self::POOL_ID, 'a-rotated-policy');

        $this->assertSame(
            0,
            $this->repository->getHighestGeneration(
                self::POOL_ID,
                self::POLICY,
                StatusListExpiryLaneEnum::Expiring,
            ),
        );
    }


    /**
     * @throws \Exception
     */
    public function testOffersOnlyListsOfTheRequestedLaneForAllocation(): void
    {
        $this->createList(self::LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::Expiring);
        $this->createList(self::OTHER_LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::NonExpiring);

        $expiring = $this->repository->findActiveForPolicy(
            self::POOL_ID,
            self::POLICY,
            StatusListExpiryLaneEnum::Expiring,
        );

        $this->assertCount(1, $expiring);
        $this->assertSame(self::LIST_ID, $expiring[0]->getId());
        $this->assertSame(StatusListExpiryLaneEnum::Expiring, $expiring[0]->getExpiryLane());
    }


    /**
     * A list being seeded in the other lane is not something a request in this one may stand down for:
     * it could never allocate into it, so it would give up its own list and find nothing to adopt.
     *
     * @throws \Exception
     */
    public function testDoesNotOfferListsBeingPreparedInAnotherLane(): void
    {
        $this->repository->create(
            self::LIST_ID,
            'https://op.example.org/statuslist/' . self::LIST_ID,
            self::POOL_ID,
            self::POLICY,
            StatusListExpiryLaneEnum::NonExpiring,
            1,
            1,
            self::CAPACITY,
            (string)StatusTypeEnum::Invalid->value,
            43200,
            604800,
            3600,
            'a-signing-key-id',
            StatusListKeyProfileEnum::DidJwk,
        );

        $this->assertSame(
            [],
            $this->repository->findBeingPreparedForPolicy(
                self::POOL_ID,
                self::POLICY,
                StatusListExpiryLaneEnum::Expiring,
                new DateTimeImmutable('2000-01-01 00:00:00'),
            ),
        );
    }


    /**
     * Retirement candidates are chosen by what a list holds, not by its lane, and this is the case which
     * makes that matter: a non-expiring list which was created and never allocated into names no
     * credential at all, so it is safely retirable and its entry rows are recoverable. A lane filter
     * would keep it, and its hundred and thirty thousand rows, for ever.
     *
     * @throws \Exception
     */
    public function testOffersADeactivatedNonExpiringListWhichHoldsNothing(): void
    {
        $this->createList(self::LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::NonExpiring);
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->repository->deactivate(self::LIST_ID);
        $this->backdateDeactivation(self::LIST_ID, '2026-01-01 09:00:00');

        $this->assertSame(
            [self::LIST_ID],
            $this->repository->findRetirementCandidates(new DateTimeImmutable('2026-08-07 12:00:00'), 10),
        );
    }


    /**
     * A list is only ever selected for allocation while its pool and policy fingerprint match the
     * current configuration, so one created under a policy which has since changed is unreachable. It
     * would never fill, so nothing would ever deactivate it, and every later step of the lifecycle
     * begins with deactivation.
     *
     * @throws \Exception
     */
    public function testDeactivatesListsCreatedUnderASupersededPolicy(): void
    {
        $this->createList(self::LIST_ID, 1, self::POOL_ID, 'the-old-policy');

        $this->assertSame(1, $this->repository->deactivateSuperseded([$this->target('the-current-policy')]));

        $statusList = $this->repository->findByIdOnPrimary(self::LIST_ID);

        $this->assertFalse($statusList?->isActive());
        $this->assertInstanceOf(DateTimeImmutable::class, $statusList?->getDeactivatedAt());
    }


    /**
     * @throws \Exception
     */
    public function testLeavesListsOfTheCurrentPolicyActive(): void
    {
        $this->createList();

        $this->assertSame(0, $this->repository->deactivateSuperseded([$this->target()]));
        $this->assertTrue($this->repository->findByIdOnPrimary(self::LIST_ID)?->isActive());
    }


    /**
     * @throws \Exception
     */
    public function testDeactivatesListsOfAPoolWhichIsNoLongerConfigured(): void
    {
        $this->createList(self::LIST_ID, 1, 'a-removed-pool');

        $this->assertSame(1, $this->repository->deactivateSuperseded([$this->target()]));
        $this->assertFalse($this->repository->findByIdOnPrimary(self::LIST_ID)?->isActive());
    }


    /**
     * @throws \Exception
     */
    public function testDeactivatesEverythingWhenNoPoolIsConfigured(): void
    {
        $this->createList();
        $this->createList(self::OTHER_LIST_ID, 2);

        $this->assertSame(2, $this->repository->deactivateSuperseded([]));
    }


    /**
     * A list is created inactive and stays that way while its entries are seeded. Stamping one of those
     * as deactivated would move it out of the path which deletes an abandoned seed and into the one
     * which retires a list that was served.
     *
     * @throws \Exception
     */
    public function testLeavesListsWhichAreStillBeingSeededAlone(): void
    {
        $this->repository->create(
            self::LIST_ID,
            'https://op.example.org/statuslist/' . self::LIST_ID,
            self::POOL_ID,
            'the-old-policy',
            StatusListExpiryLaneEnum::Expiring,
            1,
            1,
            self::CAPACITY,
            (string)StatusTypeEnum::Invalid->value,
            43200,
            604800,
            3600,
            'a-signing-key-id',
            StatusListKeyProfileEnum::DidJwk,
        );

        $this->assertSame(0, $this->repository->deactivateSuperseded([$this->target('the-current-policy')]));
        $this->assertNull($this->repository->findByIdOnPrimary(self::LIST_ID)?->getDeactivatedAt());
    }


    /**
     * @throws \Exception
     */
    public function testFindsListsDeactivatedBeforeTheCutOff(): void
    {
        $this->createList();
        $this->repository->deactivate(self::LIST_ID);
        $this->backdateDeactivation(self::LIST_ID, '2026-01-01 09:00:00');

        $this->assertSame(
            [self::LIST_ID],
            $this->repository->findRetirementCandidates(new DateTimeImmutable('2026-08-07 12:00:00'), 10),
        );
    }


    /**
     * @throws \Exception
     */
    public function testDoesNotOfferListsDeactivatedTooRecently(): void
    {
        $this->createList();
        $this->repository->deactivate(self::LIST_ID);

        $this->assertSame(
            [],
            $this->repository->findRetirementCandidates(new DateTimeImmutable('2020-01-01 00:00:00'), 10),
        );
    }


    /**
     * @throws \Exception
     */
    public function testDoesNotOfferListsWhichAreStillActive(): void
    {
        $this->createList();

        $this->assertSame(
            [],
            $this->repository->findRetirementCandidates(new DateTimeImmutable('2099-01-01 00:00:00'), 10),
        );
    }


    /**
     * Inactive with no deactivation stamp is a list whose entries are still being seeded, or one whose
     * seeding was abandoned. Neither is retired; an abandoned one is deleted outright.
     *
     * @throws \Exception
     */
    public function testDoesNotOfferListsWhichWereNeverOpened(): void
    {
        $this->repository->create(
            self::LIST_ID,
            'https://op.example.org/statuslist/' . self::LIST_ID,
            self::POOL_ID,
            self::POLICY,
            StatusListExpiryLaneEnum::Expiring,
            1,
            1,
            self::CAPACITY,
            (string)StatusTypeEnum::Invalid->value,
            43200,
            604800,
            3600,
            'a-signing-key-id',
            StatusListKeyProfileEnum::DidJwk,
        );

        $this->assertSame(
            [],
            $this->repository->findRetirementCandidates(new DateTimeImmutable('2099-01-01 00:00:00'), 10),
        );
    }


    /**
     * A list holding a credential without an expiry is not waiting for anything -- it can never be
     * retired. Leaving it among the candidates would let a deployment with enough of them fill every
     * batch a run works through and starve the lists behind them, and since every run starts from the
     * beginning that would not correct itself.
     *
     * @throws \Exception
     */
    public function testDoesNotOfferListsWhichCanNeverBeRetired(): void
    {
        $this->createList(self::LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::NonExpiring);
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->entryRepository->allocate(
            self::LIST_ID,
            0,
            'urn:vc:permanent',
            $this->entryRepository->hashCredentialId('urn:vc:permanent'),
            'UniversityDegree',
            null,
            null,
        );
        $this->repository->deactivate(self::LIST_ID);
        $this->backdateDeactivation(self::LIST_ID, '2026-01-01 09:00:00');

        $this->assertSame(
            [],
            $this->repository->findRetirementCandidates(new DateTimeImmutable('2026-08-07 12:00:00'), 10),
        );
    }


    /**
     * Unallocated entries have no expiry either, and there is one for every index of the list from the
     * moment it is created, so an exclusion which did not filter on allocation would rule out every
     * list there is.
     *
     * @throws \Exception
     */
    public function testStillOffersAListWhoseUnusedIndicesHaveNoExpiry(): void
    {
        $this->createList();
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->entryRepository->allocate(
            self::LIST_ID,
            0,
            'urn:vc:expiring',
            $this->entryRepository->hashCredentialId('urn:vc:expiring'),
            'UniversityDegree',
            null,
            new DateTimeImmutable('2026-06-01 09:00:00'),
        );
        $this->repository->deactivate(self::LIST_ID);
        $this->backdateDeactivation(self::LIST_ID, '2026-01-01 09:00:00');

        $this->assertSame(
            [self::LIST_ID],
            $this->repository->findRetirementCandidates(new DateTimeImmutable('2026-08-07 12:00:00'), 10),
        );
    }


    /**
     * @throws \Exception
     */
    public function testDoesNotOfferListsWhichAreAlreadyRetired(): void
    {
        $this->createList();
        $this->repository->deactivate(self::LIST_ID);
        $this->backdateDeactivation(self::LIST_ID, '2026-01-01 09:00:00');
        $this->repository->retire(self::LIST_ID, $this->spentBefore());

        $this->assertSame(
            [],
            $this->repository->findRetirementCandidates(new DateTimeImmutable('2026-08-07 12:00:00'), 10),
        );
    }


    /**
     * Retiring a list takes it out of the set being paged through, so an offset would step over exactly
     * as many unexamined lists as were retired.
     *
     * @throws \Exception
     */
    public function testPagesRetirementCandidatesByCursor(): void
    {
        $this->createList('list-a');
        $this->createList('list-b', 2);
        $this->createList('list-c', 3);

        foreach (['list-a', 'list-b', 'list-c'] as $id) {
            $this->repository->deactivate($id);
            $this->backdateDeactivation($id, '2026-01-01 09:00:00');
        }

        $cutOff = new DateTimeImmutable('2026-08-07 12:00:00');

        $this->assertSame(['list-a', 'list-b'], $this->repository->findRetirementCandidates($cutOff, 2));
        $this->assertSame(['list-c'], $this->repository->findRetirementCandidates($cutOff, 2, 'list-b'));
    }


    /**
     * @throws \Exception
     */
    public function testRetirementStampsTheListAndGivesBackItsToken(): void
    {
        $this->createList();
        $this->repository->publishToken(
            self::LIST_ID,
            '',
            0,
            'a-content-hash',
            'a.signed.token',
            new DateTimeImmutable('2026-08-01 09:00:00'),
            new DateTimeImmutable('2026-08-08 09:00:00'),
        );
        $this->repository->deactivate(self::LIST_ID);

        $this->assertTrue($this->repository->retire(self::LIST_ID, $this->spentBefore()));

        $statusList = $this->repository->findByIdOnPrimary(self::LIST_ID);

        $this->assertTrue($statusList?->isRetired());
        $this->assertNull($statusList?->getSignedToken());
        $this->assertSame('', $statusList?->getSignedTokenContentHash());
    }


    /**
     * The counter is what keeps a signer which is mid-flight from publishing a token onto a list which
     * has just been retired out from under it.
     *
     * @throws \Exception
     */
    public function testRetirementMovesTheInvalidationCounter(): void
    {
        $this->createList();
        $this->repository->deactivate(self::LIST_ID);

        $before = $this->repository->findByIdOnPrimary(self::LIST_ID)?->getInvalidationCounter();

        $this->repository->retire(self::LIST_ID, $this->spentBefore());

        $this->assertSame(
            (int)$before + 1,
            $this->repository->findByIdOnPrimary(self::LIST_ID)?->getInvalidationCounter(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testRefusesToRetireAListWhichIsStillActive(): void
    {
        $this->createList();

        $this->assertFalse($this->repository->retire(self::LIST_ID, $this->spentBefore()));
        $this->assertFalse($this->repository->findByIdOnPrimary(self::LIST_ID)?->isRetired());
    }


    /**
     * Of several workers deciding at the same moment, only one should report having retired it.
     *
     * @throws \Exception
     */
    public function testOnlyTheFirstCallRetiresAList(): void
    {
        $this->createList();
        $this->repository->deactivate(self::LIST_ID);

        $this->assertTrue($this->repository->retire(self::LIST_ID, $this->spentBefore()));
        $this->assertFalse($this->repository->retire(self::LIST_ID, $this->spentBefore()));
    }


    /**
     * @throws \Exception
     */
    protected function allocateEntry(int $idx, string $credentialId, ?DateTimeImmutable $expiresAt): void
    {
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->entryRepository->allocate(
            self::LIST_ID,
            $idx,
            $credentialId,
            $this->entryRepository->hashCredentialId($credentialId),
            'UniversityDegree',
            null,
            $expiresAt,
        );
    }


    /**
     * The whole point of testing the expiry inside the retiring statement: a caller which read the
     * entries, decided they had all expired, and retired the list in a second statement would leave a
     * gap that an issuance already in flight could land in, and there are no transactions to close it.
     *
     * @throws \Exception
     */
    public function testRefusesToRetireAListWhichStillHoldsALiveCredential(): void
    {
        $this->createList();
        $this->allocateEntry(0, 'urn:vc:live', new DateTimeImmutable('2027-06-01 09:00:00'));
        $this->repository->deactivate(self::LIST_ID);

        $this->assertFalse(
            $this->repository->retire(self::LIST_ID, new DateTimeImmutable('2026-08-07 12:00:00')),
        );
        $this->assertFalse($this->repository->findByIdOnPrimary(self::LIST_ID)?->isRetired());
    }


    /**
     * @throws \Exception
     */
    public function testRetiresAListWhoseCredentialsHaveAllExpired(): void
    {
        $this->createList();
        $this->allocateEntry(0, 'urn:vc:expired', new DateTimeImmutable('2026-01-01 09:00:00'));
        $this->repository->deactivate(self::LIST_ID);

        $this->assertTrue(
            $this->repository->retire(self::LIST_ID, new DateTimeImmutable('2026-08-07 12:00:00')),
        );
    }


    /**
     * @throws \Exception
     */
    public function testNeverRetiresAListHoldingACredentialWithoutAnExpiry(): void
    {
        $this->createList(self::LIST_ID, 1, self::POOL_ID, self::POLICY, StatusListExpiryLaneEnum::NonExpiring);
        $this->allocateEntry(0, 'urn:vc:permanent', null);
        $this->repository->deactivate(self::LIST_ID);

        $this->assertFalse(
            $this->repository->retire(self::LIST_ID, new DateTimeImmutable('2099-01-01 00:00:00')),
        );
    }


    /**
     * Every index exists as a row from the moment the list is created and an unallocated one has no
     * expiry, so a guard which did not filter on allocation would refuse to retire any list at all.
     *
     * @throws \Exception
     */
    public function testTheUnusedIndicesOfAListDoNotKeepItFromRetiring(): void
    {
        $this->createList();
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->repository->deactivate(self::LIST_ID);

        $this->assertTrue(
            $this->repository->retire(self::LIST_ID, new DateTimeImmutable('2026-08-07 12:00:00')),
        );
    }


    /**
     * @throws \Exception
     */
    public function testFindsRetiredListsWhichStillHaveEntries(): void
    {
        $this->createList();
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->repository->deactivate(self::LIST_ID);
        $this->repository->retire(self::LIST_ID, $this->spentBefore());

        $this->assertSame([self::LIST_ID], $this->repository->findRetiredWithEntries(10, $this->spentBefore()));
    }


    /**
     * Removing the entries is bounded, so the same list is found again by run after run. Once it has
     * none left it has to drop out, otherwise every list a deployment ever retired would be re-examined
     * for ever.
     *
     * @throws \Exception
     */
    public function testStopsOfferingARetiredListOnceItsEntriesAreGone(): void
    {
        $this->createList();
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->repository->deactivate(self::LIST_ID);
        $this->repository->retire(self::LIST_ID, $this->spentBefore());
        $this->entryRepository->deleteRetiredEntries(self::LIST_ID, self::CAPACITY);

        $this->assertSame([], $this->repository->findRetiredWithEntries(10, $this->spentBefore()));
    }


    /**
     * Retirement can not be serialised against an issuance which was already in flight, so a credential
     * can in principle be written into a list just after it was retired. Retirement alone leaves that
     * credential unverifiable; removing the entries too would leave nothing to show it was ever issued.
     *
     * @throws \Exception
     */
    public function testDoesNotOfferAListRetiredTooRecentlyToPurge(): void
    {
        $this->createList();
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->repository->deactivate(self::LIST_ID);
        $this->repository->retire(self::LIST_ID, $this->spentBefore());

        // Retired just now, so a cut-off in the past excludes it.
        $this->assertSame(
            [],
            $this->repository->findRetiredWithEntries(10, new DateTimeImmutable('2020-01-01 00:00:00')),
        );
    }


    /**
     * @throws \Exception
     */
    public function testDoesNotOfferEntriesOfListsWhichAreNotRetired(): void
    {
        $this->createList();
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);

        $this->assertSame([], $this->repository->findRetiredWithEntries(10, $this->spentBefore()));
    }


    /**
     * A raw row as the database actually holds it, for the tests which stand a mocked connection in
     * front of the repository. Hand written column lists drift; this one cannot say anything the schema
     * does not.
     *
     * @return array<string,mixed>
     * @throws \Exception
     */
    protected function rawRow(string $id): array
    {
        /** @var array<array-key,mixed> $rows */
        $rows = Database::getInstance()->readPrimary(
            sprintf('SELECT * FROM %s WHERE id = :id', $this->repository->getTableName()),
            ['id' => $id],
        )->fetchAll();

        $this->assertArrayHasKey(0, $rows);
        $this->assertIsArray($rows[0]);

        return $rows[0];
    }


    /**
     * @param array<array-key,mixed> $rows
     */
    protected function statementReturning(array $rows): PDOStatement&MockObject
    {
        $statementMock = $this->createMock(PDOStatement::class);
        $statementMock->method('fetchAll')->willReturn($rows);

        return $statementMock;
    }


    /**
     * @throws \Exception
     */
    protected function repositoryOver(Database $database): StatusListRepository
    {
        return new StatusListRepository($this->moduleConfigMock, $database, null, $this->helpers);
    }


    /**
     * @throws \Exception
     */
    protected function countEntryRows(string $statusListId): int
    {
        /** @var array<array-key,mixed> $rows */
        $rows = Database::getInstance()->readPrimary(
            sprintf(
                'SELECT COUNT(*) AS row_count FROM %s WHERE status_list_id = :status_list_id',
                $this->entryRepository->getTableName(),
            ),
            ['status_list_id' => $statusListId],
        )->fetchAll();

        $this->assertArrayHasKey(0, $rows);
        $this->assertIsArray($rows[0]);

        return (int)$rows[0]['row_count'];
    }


    /**
     * Stamps a list as retired while leaving its published token where it is, which retirement itself
     * never does. The test which uses it explains why that state is worth constructing.
     *
     * @throws \Exception
     */
    protected function stampRetirement(string $id, string $retiredAt): void
    {
        Database::getInstance()->write(
            sprintf('UPDATE %s SET retired_at = :retired_at WHERE id = :id', $this->repository->getTableName()),
            [
                'retired_at' => $retiredAt,
                'id' => $id,
            ],
        );
    }


    /**
     * @throws \Exception
     */
    protected function publish(
        string $contentHash,
        string $observedContentHash = '',
        int $observedInvalidationCounter = 0,
        string $issuedAt = '2026-08-01 09:00:00',
        string $id = self::LIST_ID,
    ): bool {
        return $this->repository->publishToken(
            $id,
            $observedContentHash,
            $observedInvalidationCounter,
            $contentHash,
            'a.signed.token.for.' . $contentHash,
            // Zoned explicitly. The repository converts a moment to UTC on the way in and the record
            // reads it back as UTC, so a fixture left to the process default would round trip only
            // where that default is already UTC, and the assertions below on an exact issuance time
            // would be off by the offset anywhere else.
            new DateTimeImmutable($issuedAt, new DateTimeZone('UTC')),
            new DateTimeImmutable('2026-08-08 09:00:00', new DateTimeZone('UTC')),
        );
    }


    /**
     * The endpoint reads a secondary, and a secondary is allowed to be behind. Being behind can only
     * ever cost a token some staleness the `ttl` claim already sanctions, with one exception: a list
     * created moments ago is missing rather than stale, and answering "no such list" would 404 a
     * credential which was issued and does exist. So a miss, and only a miss, is asked again of the
     * primary.
     *
     * The connection is mocked here because a real one cannot show this. Both reads reach the same
     * SQLite database, so a repository which had lost the second read entirely would return exactly
     * what one which kept it returns.
     *
     * @throws \Exception
     */
    public function testAListMissingFromASecondaryIsLookedForAgainOnThePrimary(): void
    {
        $this->createList();

        $databaseMock = $this->createMock(Database::class);
        $databaseMock->method('read')->willReturn($this->statementReturning([]));
        $databaseMock->expects($this->once())
            ->method('readPrimary')
            ->willReturn($this->statementReturning([$this->rawRow(self::LIST_ID)]));

        $this->assertSame(
            self::LIST_ID,
            $this->repositoryOver($databaseMock)->findById(self::LIST_ID)?->getId(),
        );
    }


    /**
     * The other half of the same decision, and the half which stops the fix for staleness from being
     * "read the primary always". This read is the one the status list endpoint serves every wallet
     * from, and it is on a secondary deliberately; a second read on the way past would put the whole of
     * that traffic back on the primary while changing nothing a wallet can observe.
     *
     * @throws \Exception
     */
    public function testAListFoundOnASecondaryIsNotLookedForAgainOnThePrimary(): void
    {
        $this->createList();

        $databaseMock = $this->createMock(Database::class);
        $databaseMock->method('read')->willReturn(
            $this->statementReturning([$this->rawRow(self::LIST_ID)]),
        );
        $databaseMock->expects($this->never())->method('readPrimary');

        $this->assertSame(
            self::LIST_ID,
            $this->repositoryOver($databaseMock)->findById(self::LIST_ID)?->getId(),
        );
    }


    /**
     * A request which finds no list to allocate into creates one, and before it does it looks for a
     * list another request created a moment ago and has not opened yet, so that the two do not both
     * create one. This is that query returning something.
     *
     * @throws \Exception
     */
    public function testOffersAListWhichAnotherRequestIsStillPreparing(): void
    {
        $this->createList(activate: false);

        $beingPrepared = $this->repository->findBeingPreparedForPolicy(
            self::POOL_ID,
            self::POLICY,
            StatusListExpiryLaneEnum::Expiring,
            new DateTimeImmutable('2000-01-01 00:00:00'),
        );

        $this->assertCount(1, $beingPrepared);
        $this->assertSame(self::LIST_ID, $beingPrepared[0]->getId());
    }


    /**
     * Once a list is open it is no longer something to stand down for: it is found by the query which
     * looks for lists to allocate into, and a request which adopted it here as well would be counting
     * the same list twice.
     *
     * @throws \Exception
     */
    public function testDoesNotOfferAListWhichHasAlreadyBeenOpened(): void
    {
        $this->createList();

        $this->assertSame(
            [],
            $this->repository->findBeingPreparedForPolicy(
                self::POOL_ID,
                self::POLICY,
                StatusListExpiryLaneEnum::Expiring,
                new DateTimeImmutable('2000-01-01 00:00:00'),
            ),
        );
    }


    /**
     * The cap is how a request which has already claimed a generation asks only about generations below
     * its own. Without it two requests which each created a list would each adopt the other's and both
     * abandon their own, leaving the pool with no open list at all.
     *
     * @throws \Exception
     */
    public function testOffersOnlyListsBelowTheGenerationAskedAbout(): void
    {
        $this->createList(self::LIST_ID, 1, activate: false);
        $this->createList(self::OTHER_LIST_ID, 2, activate: false);

        $this->assertSame(
            [self::LIST_ID],
            array_map(
                static fn(StatusListRecord $record): string => $record->getId(),
                $this->repository->findBeingPreparedForPolicy(
                    self::POOL_ID,
                    self::POLICY,
                    StatusListExpiryLaneEnum::Expiring,
                    new DateTimeImmutable('2000-01-01 00:00:00'),
                    2,
                ),
            ),
        );
    }


    /**
     * With no cap the caller is asking what is being prepared at all, which is a different question
     * from what it may stand down for.
     *
     * @throws \Exception
     */
    public function testOffersEveryGenerationWhenNoneIsNamed(): void
    {
        $this->createList(self::LIST_ID, 1, activate: false);
        $this->createList(self::OTHER_LIST_ID, 2, activate: false);

        $this->assertCount(
            2,
            $this->repository->findBeingPreparedForPolicy(
                self::POOL_ID,
                self::POLICY,
                StatusListExpiryLaneEnum::Expiring,
                new DateTimeImmutable('2000-01-01 00:00:00'),
            ),
        );
    }


    /**
     * The entries are removed explicitly rather than left to the foreign key. The constraint is declared
     * ON DELETE CASCADE, but SQLite only enforces foreign keys when the connection asks it to and this
     * module's wrapper does not ask, so a repository which relied on the cascade would leave every entry
     * behind on one of the three supported drivers. That is the assertion on the entry count below: on
     * this connection it is the cascade which is absent, not the rows.
     *
     * @throws \Exception
     */
    public function testDeletesAnUnopenedListTogetherWithTheEntriesItSeeded(): void
    {
        $this->createList(activate: false);
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);

        $this->assertTrue($this->repository->deleteUnopened(self::LIST_ID));
        $this->assertNull($this->repository->findByIdOnPrimary(self::LIST_ID));
        $this->assertSame(0, $this->countEntryRows(self::LIST_ID));
    }


    /**
     * A list's URI is handed out the moment it is opened, so an open list may already be named by a
     * credential somewhere. Nothing this method does is allowed to reach one.
     *
     * @throws \Exception
     */
    public function testRefusesToDeleteAListWhichHasBeenOpened(): void
    {
        $this->createList();
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);

        $this->assertFalse($this->repository->deleteUnopened(self::LIST_ID));
        $this->assertNotNull($this->repository->findByIdOnPrimary(self::LIST_ID));
        $this->assertSame(self::CAPACITY, $this->countEntryRows(self::LIST_ID));
    }


    /**
     * A deactivated list was open once, which is the whole of the reason: it is not active now, so the
     * active check alone would let it through, and it may well be named by credentials issued while it
     * was.
     *
     * @throws \Exception
     */
    public function testRefusesToDeleteAListWhichWasOpenedAndThenDeactivated(): void
    {
        $this->createList();
        $this->entryRepository->seed(self::LIST_ID, self::CAPACITY);
        $this->repository->deactivate(self::LIST_ID);

        $this->assertFalse($this->repository->deleteUnopened(self::LIST_ID));
        $this->assertNotNull($this->repository->findByIdOnPrimary(self::LIST_ID));
        $this->assertSame(self::CAPACITY, $this->countEntryRows(self::LIST_ID));
    }


    /**
     * Which is also what a second call sees, so the operation is safe to repeat.
     *
     * @throws \Exception
     */
    public function testReportsNothingDeletedForAListWhichIsNotThere(): void
    {
        $this->assertFalse($this->repository->deleteUnopened(self::LIST_ID));
    }


    /**
     * The counter is per list, and advisory: it decides when a pool is worth considering for rotation.
     * A count which leaked between lists would rotate pools which had issued nothing.
     *
     * @throws \Exception
     */
    public function testCountsAnAllocationAgainstTheListItWasMadeIn(): void
    {
        $this->createList();
        $this->createList(self::OTHER_LIST_ID, 2);

        $this->repository->incrementAllocatedCount(self::LIST_ID);
        $this->repository->incrementAllocatedCount(self::LIST_ID);

        $this->assertSame(2, $this->repository->findByIdOnPrimary(self::LIST_ID)?->getAllocatedCount());
        $this->assertSame(0, $this->repository->findByIdOnPrimary(self::OTHER_LIST_ID)?->getAllocatedCount());
    }


    /**
     * @throws \Exception
     */
    public function testInvalidatingAPublishedTokenClearsItsHashAndMovesTheCounter(): void
    {
        $this->createList();
        $this->assertTrue($this->publish('a-content-hash'));

        $this->repository->invalidatePublishedToken(self::LIST_ID);

        $statusList = $this->repository->findByIdOnPrimary(self::LIST_ID);

        $this->assertSame('', $statusList?->getSignedTokenContentHash());
        $this->assertSame(1, $statusList?->getInvalidationCounter());
    }


    /**
     * The counter moves even when there was nothing published to clear, and that is the point of it.
     * Clearing an already empty hash says nothing, so a signer which read that empty hash before this
     * call would still match it afterwards and publish a token built before the change -- and with this
     * writer finished, nothing would clear it again. The counter is what that signer fails against.
     *
     * @throws \Exception
     */
    public function testInvalidatingMovesTheCounterEvenWithNothingPublished(): void
    {
        $this->createList();

        $this->repository->invalidatePublishedToken(self::LIST_ID);

        // Only the counter is asserted. A list is created with an empty hash, so an assertion that the
        // hash is empty afterwards would hold whether or not this statement touched the row at all.
        $this->assertSame(
            1,
            $this->repository->findByIdOnPrimary(self::LIST_ID)?->getInvalidationCounter(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testPublishesATokenWhoseSnapshotIsStillTheCurrentContent(): void
    {
        $this->createList();

        $this->assertTrue($this->publish('a-content-hash'));

        $statusList = $this->repository->findByIdOnPrimary(self::LIST_ID);

        $this->assertSame('a.signed.token.for.a-content-hash', $statusList?->getSignedToken());
        $this->assertSame('a-content-hash', $statusList?->getSignedTokenContentHash());
        $this->assertSame(
            '2026-08-01 09:00:00',
            $statusList?->getSignedTokenIssuedAt()?->format('Y-m-d H:i:s'),
        );
    }


    /**
     * Two requests both found the token stale and both signed one. The first to arrive matches the hash
     * it observed and publishes; the second no longer does, and must re-read rather than overwrite a
     * token which is newer than the snapshot it signed over.
     *
     * @throws \Exception
     */
    public function testRefusesATokenWhoseObservedContentHasSinceBeenReplaced(): void
    {
        $this->createList();
        $this->assertTrue($this->publish('the-first-hash'));

        // The second signer publishes against the empty hash it read before the first one arrived.
        $this->assertFalse($this->publish('a-later-hash'));
        $this->assertSame(
            'a.signed.token.for.the-first-hash',
            $this->repository->findByIdOnPrimary(self::LIST_ID)?->getSignedToken(),
        );
    }


    /**
     * The case the counter exists for, and the one the hash cannot decide on its own.
     *
     * An empty hash means both "never published" and "invalidated since". A signer which took its
     * snapshot of an unpublished list, and had a revocation land while it was signing, observes the
     * same empty hash afterwards as it did before -- so on the hash alone it would publish a token
     * which predates the revocation, over a list which has just been revoked in.
     *
     * @throws \Exception
     */
    public function testRefusesATokenWhoseSnapshotWasSupersededWhileTheHashStayedEmpty(): void
    {
        $this->createList();

        // The signer reads an unpublished list: no hash, no invalidations yet. It begins signing.
        // A revocation lands while it does, which leaves the hash exactly as the signer found it.
        $this->repository->invalidatePublishedToken(self::LIST_ID);

        $this->assertFalse($this->publish('a-content-hash', observedInvalidationCounter: 0));
        $this->assertNull($this->repository->findByIdOnPrimary(self::LIST_ID)?->getSignedToken());
    }


    /**
     * Re-signing content which has not changed compares a hash against itself, which settles nothing:
     * two nodes refreshing the same unchanged list would both match, and both publish. Requiring the
     * new issuance time to be strictly later leaves one winner.
     *
     * The guard is on this path only. Applied to publications which change the content, a node whose
     * clock ran behind another's could not publish a revocation until its clock caught up.
     *
     * @throws \Exception
     */
    public function testRepublishingUnchangedContentNeedsAStrictlyLaterIssuanceTime(): void
    {
        $this->createList();
        $this->assertTrue($this->publish('a-content-hash', issuedAt: '2026-08-01 09:00:00'));

        $this->assertFalse(
            $this->publish('a-content-hash', 'a-content-hash', 0, '2026-08-01 08:59:59'),
            'A token issued before the published one replaced it.',
        );
        $this->assertFalse(
            $this->publish('a-content-hash', 'a-content-hash', 0, '2026-08-01 09:00:00'),
            'A token issued at the same moment as the published one replaced it.',
        );
        $this->assertTrue(
            $this->publish('a-content-hash', 'a-content-hash', 0, '2026-08-01 09:00:01'),
            'A token issued after the published one did not replace it.',
        );

        $this->assertSame(
            '2026-08-01 09:00:01',
            $this->repository->findByIdOnPrimary(self::LIST_ID)?->getSignedTokenIssuedAt()?->format('Y-m-d H:i:s'),
        );
    }


    /**
     * A list with nothing published has nothing for the reconciler to check.
     *
     * @throws \Exception
     */
    public function testOffersOnlyListsWhichHaveSomethingPublished(): void
    {
        $this->createList();
        $this->createList(self::OTHER_LIST_ID, 2);
        $this->assertTrue($this->publish('a-content-hash'));

        $published = $this->repository->findPublished(10);

        $this->assertCount(1, $published);
        $this->assertSame(self::LIST_ID, $published[0]->getId());
    }


    /**
     * A retired list keeps being served until its entries are purged, but its content can no longer
     * change, so there is nothing for the reconciler to find and re-checking it every pass is waste.
     *
     * The row is put into this state directly rather than by retiring a list, and that is the whole
     * point of the test. Retirement clears the published token on its way past, so a list retired
     * through the repository is already excluded by its empty hash, and a test which went that way
     * could not tell whether the retirement condition does any work of its own. This one can.
     *
     * @throws \Exception
     */
    public function testDoesNotOfferListsWhichHaveBeenRetired(): void
    {
        $this->createList();
        $this->assertTrue($this->publish('a-content-hash'));
        $this->stampRetirement(self::LIST_ID, '2026-08-02 09:00:00');

        $this->assertSame([], $this->repository->findPublished(10));
    }


    /**
     * Paged by the last identifier seen rather than by an offset, because the caller invalidates some
     * of the rows it is given and that removes them from this result set. An offset would step over
     * exactly as many unexamined lists as were invalidated.
     *
     * @throws \Exception
     */
    public function testPagesPublishedListsByTheLastIdentifierSeen(): void
    {
        $ids = ['list-a', 'list-b', 'list-c'];

        foreach ($ids as $generation => $id) {
            $this->createList($id, $generation + 1);
            $this->assertTrue($this->publish('a-content-hash', id: $id));
        }

        $firstPage = $this->repository->findPublished(2);
        $this->assertSame(
            ['list-a', 'list-b'],
            array_map(static fn(StatusListReconciliationCandidate $c): string => $c->getId(), $firstPage),
        );

        $secondPage = $this->repository->findPublished(2, $firstPage[1]->getId());
        $this->assertSame(
            ['list-c'],
            array_map(static fn(StatusListReconciliationCandidate $c): string => $c->getId(), $secondPage),
        );

        // The cursor resumes strictly after the identifier it was given, so the reconciler cannot be
        // handed the same list twice and cannot loop on it.
        $this->assertSame([], $this->repository->findPublished(2, 'list-c'));
    }


    /**
     * The limit reaches the statement interpolated rather than bound, because MySQL rejects a bound
     * LIMIT while PDO emulates prepared statements. It is clamped on the way past, so a caller which
     * asked for nothing gets nothing rather than a statement which will not parse.
     *
     * @throws \Exception
     */
    public function testAsksTheDatabaseForNothingWhenNothingWasAskedFor(): void
    {
        $this->createList();
        $this->assertTrue($this->publish('a-content-hash'));

        $this->assertSame([], $this->repository->findPublished(0));
        $this->assertSame([], $this->repository->findPublished(-1));
    }


    /**
     * Only the columns the reconciler compares are read. A row carries its published token, which for
     * an eight bit list at the default capacity is a couple of hundred kilobytes, and reading whole
     * rows would move tens of megabytes a batch for a check which never looks at one.
     *
     * @throws \Exception
     */
    public function testCarriesEveryColumnTheReconcilerComparesAgainst(): void
    {
        // Three of the columns this statement names are integers: bits, capacity and the
        // invalidation counter. The row holds nine integer columns counting the active flag, so each
        // of the three is given a value none of the rest holds -- a statement naming the wrong column
        // reads exactly like one naming the right column for as long as the two agree. Four bits
        // rather than the usual one is what that costs here, the active flag of an opened list being
        // stored as 1 and bits having been 1 as well.
        $this->createList(self::LIST_ID, 7, bits: 4);
        $this->assertTrue($this->publish('a-content-hash'));
        $this->repository->invalidatePublishedToken(self::LIST_ID);
        $this->repository->invalidatePublishedToken(self::LIST_ID);
        $this->assertTrue($this->publish('a-later-hash', observedInvalidationCounter: 2));

        $candidate = $this->repository->findPublished(10)[0];

        $this->assertSame(self::LIST_ID, $candidate->getId());
        $this->assertSame(4, $candidate->getBits());
        $this->assertSame(self::CAPACITY, $candidate->getCapacity());
        $this->assertSame('a-later-hash', $candidate->getSignedTokenContentHash());
        $this->assertSame(2, $candidate->getInvalidationCounter());
    }


    /**
     * @throws \Exception
     */
    public function testClearsAPublishedTokenWhichIsStillTheOneThatWasExamined(): void
    {
        $this->createList();
        $this->assertTrue($this->publish('a-content-hash'));

        $this->assertTrue(
            $this->repository->invalidatePublishedTokenIfUnchanged(self::LIST_ID, 'a-content-hash', 0),
        );

        $statusList = $this->repository->findByIdOnPrimary(self::LIST_ID);

        $this->assertSame('', $statusList?->getSignedTokenContentHash());
        // Moved for the reason the unconditional invalidation moves it: a signer which read the token
        // this call just cleared must not match the row it has been left with.
        $this->assertSame(1, $statusList?->getInvalidationCounter());
    }


    /**
     * The case the counter decides, and the one the hash cannot.
     *
     * Between the reconciler's read and its decision, a revocation cleared the token it examined and a
     * signer published a new one over the same content. The hash on the row is therefore the hash the
     * reconciler saw, while what it saw is two publications out of date -- so on the hash alone it
     * would clear a token which is correct, and could go on defeating an in-flight signer indefinitely.
     *
     * @throws \Exception
     */
    public function testLeavesAPublishedTokenWhoseContentCameBackAfterAnInvalidation(): void
    {
        $this->createList();
        $this->assertTrue($this->publish('the-examined-hash'));

        $this->repository->invalidatePublishedToken(self::LIST_ID);
        $this->assertTrue($this->publish('the-examined-hash', observedInvalidationCounter: 1));

        $this->assertFalse(
            $this->repository->invalidatePublishedTokenIfUnchanged(self::LIST_ID, 'the-examined-hash', 0),
        );
        $this->assertSame(
            'the-examined-hash',
            $this->repository->findByIdOnPrimary(self::LIST_ID)?->getSignedTokenContentHash(),
        );
    }


    /**
     * The same decision made on the hash, which is the half a replaced token trips.
     *
     * @throws \Exception
     */
    public function testLeavesAPublishedTokenWhichWasReplacedSinceItWasExamined(): void
    {
        $this->createList();
        $this->assertTrue($this->publish('the-examined-hash'));

        // A signer publishes between the reconciler's read and its decision.
        $this->assertTrue($this->publish('a-newer-hash', observedContentHash: 'the-examined-hash'));

        $this->assertFalse(
            $this->repository->invalidatePublishedTokenIfUnchanged(self::LIST_ID, 'the-examined-hash', 0),
        );
        $this->assertSame(
            'a-newer-hash',
            $this->repository->findByIdOnPrimary(self::LIST_ID)?->getSignedTokenContentHash(),
        );
    }
}

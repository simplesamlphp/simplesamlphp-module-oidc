<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateTimeImmutable;
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
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

/**
 * The lifecycle end of the Status List repository: the states a list moves through once nothing is
 * being allocated into it any more.
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
    ): void {
        $this->repository->create(
            $id,
            'https://op.example.org/statuslist/' . $id,
            $poolId,
            $policyFingerprint,
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
        $this->repository->activate($id);
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
}

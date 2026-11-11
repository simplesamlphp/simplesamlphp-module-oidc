<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateTimeImmutable;
use DateTimeZone;
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
use SimpleSAML\Module\oidc\Repositories\CredentialOfferRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\CredentialOfferRecord;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

#[CoversClass(CredentialOfferRepository::class)]
#[AllowMockObjectsWithoutExpectations]
class CredentialOfferRepositoryTest extends TestCase
{
    use LaggingSecondaryTestTrait;


    protected const string LIST_ID = 'a-status-list-id';


    protected MockObject $moduleConfigMock;

    protected Helpers $helpers;

    protected CredentialOfferRepository $repository;

    protected StatusListEntryRepository $statusListEntryRepository;

    protected StatusListRepository $statusListRepository;


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
        $this->helpers = new Helpers();

        $this->repository = new CredentialOfferRepository(
            $this->moduleConfigMock,
            Database::getInstance(),
            null,
            $this->helpers,
        );
        $this->statusListEntryRepository = new StatusListEntryRepository(
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
        Database::getInstance()->write(sprintf('DELETE FROM %s', $this->statusListEntryRepository->getTableName()));
        Database::getInstance()->write(sprintf('DELETE FROM %s', $this->statusListRepository->getTableName()));
    }


    protected static function offerId(string $character): string
    {
        return str_repeat($character, 64);
    }


    protected function utc(string $moment): DateTimeImmutable
    {
        return new DateTimeImmutable($moment, new DateTimeZone('UTC'));
    }


    /**
     * @throws \Exception
     */
    protected function persistOffer(
        string $id,
        DateTimeImmutable $retainedUntil,
        ?string $owner = 'HR system',
    ): void {
        $this->repository->persist(new CredentialOfferRecord(
            $id,
            $owner,
            ['employee_card'],
            'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            $retainedUntil->modify('-10 minutes'),
            $retainedUntil,
            $retainedUntil,
        ));
    }


    /**
     * A credential issued from the offer, linked to it as the Credential Endpoint links one.
     *
     * @throws \Exception
     */
    protected function linkCredential(string $offerId, int $idx): void
    {
        if ($this->statusListRepository->findByIdOnPrimary(self::LIST_ID) === null) {
            $this->statusListRepository->create(
                self::LIST_ID,
                'https://op.example.org/statuslist/' . self::LIST_ID,
                'default',
                'a-policy-fingerprint',
                StatusListExpiryLaneEnum::NonExpiring,
                1,
                1,
                8,
                implode(',', [StatusTypeEnum::Valid->value, StatusTypeEnum::Invalid->value]),
                43200,
                604800,
                3600,
                'a-signing-key-id',
                StatusListKeyProfileEnum::DidJwk,
            );
            $this->statusListEntryRepository->seed(self::LIST_ID, 8);
            $this->statusListRepository->activate(self::LIST_ID);
        }

        $credentialId = 'urn:vc:' . $idx;
        $hash = $this->statusListEntryRepository->hashCredentialId($credentialId);
        $this->assertTrue($this->statusListEntryRepository->allocate(
            self::LIST_ID,
            $idx,
            $credentialId,
            $hash,
            'employee_card',
            null,
            null,
        ));
        $this->assertSame(1, $this->statusListEntryRepository->linkToOffer($offerId, [$hash]));
    }


    /**
     * @return string[]
     */
    protected function storedOfferIds(): array
    {
        $rows = Database::getInstance()->readPrimary(
            sprintf('SELECT id FROM %s ORDER BY id', $this->repository->getTableName()),
        )->fetchAll();

        return array_map(static fn(array $row): string => (string)$row['id'], $rows);
    }


    /**
     * @throws \Exception
     */
    public function testKeepsWhatAnOfferWasRecordedWith(): void
    {
        $offer = new CredentialOfferRecord(
            self::offerId('a'),
            'HR system',
            ['employee_card', 'library_card'],
            'authorization_code',
            $this->utc('2026-11-11 10:00:00'),
            $this->utc('2026-11-11 10:10:00'),
            $this->utc('2026-11-11 10:10:00'),
        );

        $this->repository->persist($offer);
        $found = $this->repository->find(self::offerId('a'));

        $this->assertInstanceOf(CredentialOfferRecord::class, $found);
        $this->assertSame(self::offerId('a'), $found->getId());
        $this->assertSame('HR system', $found->getOwner());
        $this->assertSame(['employee_card', 'library_card'], $found->getCredentialConfigurationIds());
        $this->assertSame('authorization_code', $found->getGrantType());
        $this->assertEquals($this->utc('2026-11-11 10:00:00'), $found->getCreatedAt());
        $this->assertEquals($this->utc('2026-11-11 10:10:00'), $found->getRedeemableUntil());
        $this->assertEquals($this->utc('2026-11-11 10:10:00'), $found->getRetainedUntil());
        $this->assertNull($found->getRedeemedAt());
        $this->assertNull($found->getWithdrawnAt());
    }


    /**
     * An administrator's offer has no owner, which is stored as none, never as a name.
     *
     * @throws \Exception
     */
    public function testKeepsAnOfferWithoutAnOwnerOwnerless(): void
    {
        $this->persistOffer(self::offerId('a'), $this->utc('2026-11-11 10:10:00'), null);

        $this->assertNull($this->repository->find(self::offerId('a'))?->getOwner());
    }


    /**
     * Moments are stored as their UTC wall clock, whatever zone they were made in.
     *
     * @throws \Exception
     */
    public function testStoresMomentsInUtc(): void
    {
        $this->persistOffer(
            self::offerId('a'),
            new DateTimeImmutable('2026-11-11 12:10:00', new DateTimeZone('Europe/Zagreb')),
        );

        $this->assertEquals(
            $this->utc('2026-11-11 11:10:00'),
            $this->repository->find(self::offerId('a'))?->getRetainedUntil(),
        );
    }


    public function testFindsNothingForAnUnknownOffer(): void
    {
        $this->assertNull($this->repository->find(self::offerId('b')));
    }


    /**
     * @throws \Exception
     */
    public function testKeepsTheRecordUntilTheTokenMintedForItExpires(): void
    {
        $this->persistOffer(self::offerId('a'), $this->utc('2026-11-11 10:10:00'));

        $this->assertTrue($this->repository->recordRedemption(self::offerId('a'), $this->utc('2026-11-11 11:05:00')));

        $offer = $this->repository->find(self::offerId('a'));
        $this->assertEquals($this->utc('2026-11-11 11:05:00'), $offer?->getRetainedUntil());
        $this->assertInstanceOf(DateTimeImmutable::class, $offer?->getRedeemedAt());
        // What made the offer stays as it was.
        $this->assertEquals($this->utc('2026-11-11 10:10:00'), $offer?->getRedeemableUntil());
    }


    /**
     * A second token which expires sooner than the first never shortens what the first asked for, and the first
     * redemption is the one noted. MySQL reports such an UPDATE as having changed nothing, which is why the result
     * is confirmed by reading the record rather than by the affected row count.
     *
     * @throws \Exception
     */
    public function testNeverShortensTheRecordsRetentionNorMovesItsFirstRedemption(): void
    {
        $this->persistOffer(self::offerId('a'), $this->utc('2026-11-11 10:10:00'));
        $this->assertTrue($this->repository->recordRedemption(self::offerId('a'), $this->utc('2026-11-11 11:05:00')));
        $redeemedAt = $this->repository->find(self::offerId('a'))?->getRedeemedAt();

        $this->assertTrue($this->repository->recordRedemption(self::offerId('a'), $this->utc('2026-11-11 10:30:00')));

        $offer = $this->repository->find(self::offerId('a'));
        $this->assertEquals($this->utc('2026-11-11 11:05:00'), $offer?->getRetainedUntil());
        $this->assertEquals($redeemedAt, $offer?->getRedeemedAt());
    }


    /**
     * The moment of the first redemption stays what it was, however many tokens follow.
     *
     * @throws \Exception
     */
    public function testKeepsTheMomentOfTheFirstRedemption(): void
    {
        $this->repository->persist(new CredentialOfferRecord(
            self::offerId('a'),
            'HR system',
            ['employee_card'],
            'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            $this->utc('2026-11-11 10:00:00'),
            $this->utc('2026-11-11 10:10:00'),
            $this->utc('2026-11-11 10:10:00'),
            $this->utc('2026-11-11 10:05:00'),
        ));

        $this->assertTrue($this->repository->recordRedemption(self::offerId('a'), $this->utc('2026-11-11 11:05:00')));

        $this->assertEquals(
            $this->utc('2026-11-11 10:05:00'),
            $this->repository->find(self::offerId('a'))?->getRedeemedAt(),
        );
    }


    /**
     * A token whose expiry, as stored, is earlier than the moment the offer stops being redeemable still finds
     * the record kept long enough.
     *
     * @throws \Exception
     */
    public function testConfirmsATokenWhichExpiresBeforeTheOfferStopsBeingRedeemable(): void
    {
        $this->persistOffer(self::offerId('a'), $this->utc('2026-11-11 10:10:00'));

        $this->assertTrue($this->repository->recordRedemption(self::offerId('a'), $this->utc('2026-11-11 10:05:00')));
        $this->assertEquals(
            $this->utc('2026-11-11 10:10:00'),
            $this->repository->find(self::offerId('a'))?->getRetainedUntil(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testReportsARedemptionOfAnOfferWithoutARecordAsNotRecorded(): void
    {
        $this->persistOffer(self::offerId('a'), $this->utc('2026-11-11 10:10:00'));

        $this->assertFalse($this->repository->recordRedemption(self::offerId('b'), $this->utc('2026-11-11 11:05:00')));
        $this->assertNull($this->repository->find(self::offerId('a'))?->getRedeemedAt());
    }


    /**
     * A record past its retention which no credential names goes; one still retained stays, and so does one past
     * its retention which a credential still names, until linkage cleanup lets it go.
     *
     * @throws \Exception
     */
    public function testRemovesOnlyRecordsKeptLongEnoughWhichNoCredentialNames(): void
    {
        $past = $this->helpers->dateTime()->getUtc()->modify('-1 hour');
        $future = $this->helpers->dateTime()->getUtc()->modify('+1 hour');

        $this->persistOffer(self::offerId('a'), $past);
        $this->persistOffer(self::offerId('b'), $future);
        $this->persistOffer(self::offerId('c'), $past);
        $this->linkCredential(self::offerId('c'), 0);

        $this->repository->removeExpired();

        $this->assertSame([self::offerId('b'), self::offerId('c')], $this->storedOfferIds());
    }


    /**
     * Once the linkage of the offer's last credential is cleared, nothing names the record any more and it goes.
     *
     * @throws \Exception
     */
    public function testRemovesARecordOnceNoCredentialNamesItAnyMore(): void
    {
        $this->persistOffer(self::offerId('c'), $this->helpers->dateTime()->getUtc()->modify('-1 hour'));
        $this->linkCredential(self::offerId('c'), 0);
        $this->repository->removeExpired();
        $this->assertSame([self::offerId('c')], $this->storedOfferIds());

        Database::getInstance()->write(
            sprintf('UPDATE %s SET offer_id = NULL', $this->statusListEntryRepository->getTableName()),
        );
        $this->repository->removeExpired();

        $this->assertSame([], $this->storedOfferIds());
    }


    /**
     * A record whose retention ends in a moment is kept, though nothing names it.
     *
     * @throws \Exception
     */
    public function testKeepsARecordUntilTheEndOfItsRetention(): void
    {
        $this->persistOffer(self::offerId('a'), $this->helpers->dateTime()->getUtc()->modify('+2 seconds'));

        $this->repository->removeExpired();

        $this->assertSame([self::offerId('a')], $this->storedOfferIds());
    }


    protected function repositoryBehindALaggingSecondary(): CredentialOfferRepository
    {
        return new CredentialOfferRepository(
            $this->moduleConfigMock,
            $this->databaseWithALaggingSecondary(),
            null,
            $this->helpers,
        );
    }


    /**
     * An offer is read moments after it was recorded or changed, which a secondary may not have seen yet, so it is
     * read from the primary.
     *
     * @throws \Exception
     */
    public function testFindsAnOfferJustRecordedThoughTheSecondaryHasNotCaughtUp(): void
    {
        $repository = $this->repositoryBehindALaggingSecondary();
        $this->persistOffer(self::offerId('a'), $this->utc('2026-11-11 10:10:00'));

        $this->assertSame(self::offerId('a'), $repository->find(self::offerId('a'))?->getId());
    }


    /**
     * A redemption is confirmed by what the primary holds, so a secondary which has not seen the record or the
     * raise does not refuse it.
     *
     * @throws \Exception
     */
    public function testConfirmsARedemptionThoughTheSecondaryHasNotCaughtUp(): void
    {
        $repository = $this->repositoryBehindALaggingSecondary();
        $this->persistOffer(self::offerId('a'), $this->utc('2026-11-11 10:10:00'));

        $this->assertTrue($repository->recordRedemption(self::offerId('a'), $this->utc('2026-11-11 11:05:00')));
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\integration\Repositories;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryPosition;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\CredentialOfferRecord;
use SimpleSAML\Test\Module\oidc\integration\DatabaseContainers;

/**
 * Credential offers, and the credentials linked to them, against each supported database.
 *
 * The statements here lean on what the unit tests' SQLite can not show for the other two: a CASE and a COALESCE
 * over a timestamp column and an untyped parameter, an UPDATE which MySQL reports as changing nothing when it
 * leaves a row as it was, a DELETE whose condition reads another table, and a keyset over a timestamp, a string and
 * an integer.
 */
#[CoversClass(CredentialOfferRepository::class)]
#[CoversClass(StatusListEntryRepository::class)]
#[AllowMockObjectsWithoutExpectations]
class CredentialOfferRepositoryTest extends TestCase
{
    protected const string LIST_ID = 'integration-offer-list-00000000000000000000000000000000000000000';

    protected const string OTHER_LIST_ID = 'integration-offer-list-11111111111111111111111111111111111111111';


    public static array $pgConfig;

    public static array $mysqlConfig;

    public static array $sqliteConfig;

    protected Database $database;

    protected Helpers $helpers;

    protected CredentialOfferRepository $repository;

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


    public static function databaseToTest(): array
    {
        return DatabaseContainers::all();
    }


    /**
     * @param array<string,mixed> $config
     * @throws \Exception
     */
    protected function useDatabase(array $config): void
    {
        $this->database = Database::getInstance(Configuration::loadFromArray($config, '', 'simplesaml'));
        (new DatabaseMigration($this->database))->migrate();

        $this->database->write('DELETE FROM ' . $this->database->applyPrefix(CredentialOfferRepository::TABLE_NAME));
        $this->database->write('DELETE FROM ' . $this->database->applyPrefix(StatusListEntryRepository::TABLE_NAME));
        $this->database->write('DELETE FROM ' . $this->database->applyPrefix(StatusListRepository::TABLE_NAME));

        $moduleConfig = new ModuleConfig();
        $this->helpers = new Helpers();

        $this->repository = new CredentialOfferRepository($moduleConfig, $this->database, null, $this->helpers);
        $this->statusListRepository = new StatusListRepository($moduleConfig, $this->database, null, $this->helpers);
        $this->statusListEntryRepository = new StatusListEntryRepository(
            $moduleConfig,
            $this->database,
            null,
            $this->helpers,
        );
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
    protected function persistOffer(string $id, DateTimeImmutable $retainedUntil, ?string $owner = 'HR system'): void
    {
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
     * @throws \Exception
     */
    protected function givenList(string $id, int $generation): void
    {
        $this->statusListRepository->create(
            $id,
            'https://op.example.org/module.php/oidc/statuslist/' . $id,
            'integration-offer-pool',
            'integration-offer-fingerprint',
            StatusListExpiryLaneEnum::NonExpiring,
            $generation,
            1,
            16,
            '0,1',
            43200,
            604800,
            3600,
            'integration-signing-key',
            StatusListKeyProfileEnum::DidJwk,
        );
        $this->statusListEntryRepository->seed($id, 16);
        $this->statusListRepository->activate($id);
    }


    /**
     * @throws \Exception
     */
    protected function allocate(string $statusListId, int $idx, string $credentialId, DateTimeImmutable $issuedAt): void
    {
        $this->assertTrue($this->statusListEntryRepository->allocate(
            $statusListId,
            $idx,
            $credentialId,
            $this->statusListEntryRepository->hashCredentialId($credentialId),
            'employee_card',
            null,
            null,
            $issuedAt,
        ));
    }


    /**
     * @throws \Exception
     */
    protected function link(string $offerId, string ...$credentialIds): int
    {
        return $this->statusListEntryRepository->linkToOffer(
            $offerId,
            array_map($this->statusListEntryRepository->hashCredentialId(...), $credentialIds),
        );
    }


    /**
     * @return string[]
     */
    protected function storedOfferIds(): array
    {
        $rows = $this->database->readPrimary(
            'SELECT id FROM ' . $this->database->applyPrefix(CredentialOfferRepository::TABLE_NAME) . ' ORDER BY id',
        )->fetchAll();

        return array_map(static fn(array $row): string => (string)$row['id'], $rows);
    }


    /**
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testKeepsWhatAnOfferWasRecordedWith(string $database): void
    {
        $this->useDatabase(self::$$database);

        $this->persistOffer(self::offerId('a'), $this->utc('2026-11-11 10:10:00'));
        $this->persistOffer(self::offerId('b'), $this->utc('2026-11-11 10:10:00'), null);

        $offer = $this->repository->find(self::offerId('a'));
        $this->assertSame('HR system', $offer?->getOwner());
        $this->assertSame(['employee_card'], $offer?->getCredentialConfigurationIds());
        $this->assertEquals($this->utc('2026-11-11 10:10:00'), $offer?->getRetainedUntil());
        $this->assertNull($offer?->getRedeemedAt());
        $this->assertNull($this->repository->find(self::offerId('b'))?->getOwner());
        $this->assertNull($this->repository->find(self::offerId('c')));
    }


    /**
     * The retention is raised to a later token's expiry and never lowered by a sooner one, the first redemption is
     * the one kept, and a redemption whose UPDATE changes nothing (which MySQL reports as no row affected) is still
     * confirmed.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testKeepsTheRecordUntilTheLatestTokenMintedForItExpires(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->persistOffer(self::offerId('a'), $this->utc('2026-11-11 10:10:00'));

        $this->assertTrue($this->repository->recordRedemption(self::offerId('a'), $this->utc('2026-11-11 11:05:00')));
        $redeemedAt = $this->repository->find(self::offerId('a'))?->getRedeemedAt();
        $this->assertInstanceOf(DateTimeImmutable::class, $redeemedAt);

        $this->assertTrue($this->repository->recordRedemption(self::offerId('a'), $this->utc('2026-11-11 10:30:00')));
        $this->assertTrue($this->repository->recordRedemption(self::offerId('a'), $this->utc('2026-11-11 11:05:00')));

        $offer = $this->repository->find(self::offerId('a'));
        $this->assertEquals($this->utc('2026-11-11 11:05:00'), $offer?->getRetainedUntil());
        $this->assertEquals($redeemedAt, $offer?->getRedeemedAt());

        $this->assertFalse($this->repository->recordRedemption(self::offerId('b'), $this->utc('2026-11-11 11:05:00')));
    }


    /**
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testRemovesOnlyRecordsKeptLongEnoughWhichNoCredentialNames(string $database): void
    {
        $this->useDatabase(self::$$database);
        $past = $this->helpers->dateTime()->getUtc()->modify('-1 hour');
        $future = $this->helpers->dateTime()->getUtc()->modify('+1 hour');
        $this->givenList(self::LIST_ID, 1);

        $this->persistOffer(self::offerId('a'), $past);
        $this->persistOffer(self::offerId('b'), $future);
        $this->persistOffer(self::offerId('c'), $past);
        $this->allocate(self::LIST_ID, 0, 'urn:vc:of-c', $this->utc('2026-11-11 10:00:00'));
        $this->assertSame(1, $this->link(self::offerId('c'), 'urn:vc:of-c'));

        $this->repository->removeExpired();

        $this->assertSame([self::offerId('b'), self::offerId('c')], $this->storedOfferIds());
    }


    /**
     * Linking counts what it linked, never takes a credential which already names an offer, and the listing pages
     * through a batch issued in one second, across lists, neither repeating a credential nor losing one.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testLinksAndPagesThroughTheCredentialsOfAnOffer(string $database): void
    {
        $this->useDatabase(self::$$database);
        $this->givenList(self::LIST_ID, 1);
        $this->givenList(self::OTHER_LIST_ID, 2);
        $batch = $this->utc('2026-11-11 10:00:00');
        $credentialIds = [];

        foreach ([self::LIST_ID, self::OTHER_LIST_ID] as $statusListId) {
            for ($idx = 0; $idx < 3; $idx++) {
                $credentialId = sprintf('urn:vc:%s:%d', $statusListId, $idx);
                $this->allocate($statusListId, $idx, $credentialId, $batch);
                $credentialIds[] = $credentialId;
            }
        }

        $this->allocate(self::LIST_ID, 3, 'urn:vc:later', $this->utc('2026-11-11 10:00:01'));
        $credentialIds[] = 'urn:vc:later';
        $this->allocate(self::LIST_ID, 4, 'urn:vc:of-another-offer', $batch);

        $this->assertSame(count($credentialIds), $this->link(self::offerId('a'), ...$credentialIds));
        $this->assertSame(1, $this->link(self::offerId('b'), 'urn:vc:of-another-offer'));
        $this->assertSame(0, $this->link(self::offerId('b'), $credentialIds[0]));

        $listed = [];
        $after = null;

        do {
            $page = $this->statusListEntryRepository->findLinkedToOffer(self::offerId('a'), 2, $after);
            foreach ($page as $entry) {
                $listed[] = $entry->getCredentialId();
            }
            $after = $page === [] ? null : StatusListEntryPosition::fromRecord($page[array_key_last($page)]);
        } while (count($page) === 2);

        $this->assertSame($credentialIds, $listed);
    }
}

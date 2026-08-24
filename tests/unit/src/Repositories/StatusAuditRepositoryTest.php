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
use SimpleSAML\Module\oidc\Codebooks\StatusChangeSourceEnum;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusAuditRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

#[CoversClass(StatusAuditRepository::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusAuditRepositoryTest extends TestCase
{
    protected const string CREDENTIAL_ID_HASH = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    protected const string LIST_ID = 'a-status-list-id';

    /**
     * What a statement may bind before the oldest supported driver refuses it.
     *
     * Stated here rather than read from the repository, so that the test asserts the limit the drivers
     * impose and not merely that the code agrees with itself.
     */
    protected const int MAX_BOUND_VARIABLES = 999;


    protected MockObject $moduleConfigMock;

    protected Helpers $helpers;

    protected StatusAuditRepository $repository;


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

        $this->repository = new StatusAuditRepository(
            $this->moduleConfigMock,
            Database::getInstance(),
            null,
            $this->helpers,
        );

        Database::getInstance()->write(sprintf('DELETE FROM %s', $this->repository->getTableName()));
    }


    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_status_audit', $this->repository->getTableName());
    }


    /**
     * @return array<array<string,mixed>>
     */
    protected function readRows(): array
    {
        return Database::getInstance()
            ->read(sprintf('SELECT * FROM %s ORDER BY created_at', $this->repository->getTableName()))
            ->fetchAll();
    }


    /**
     * @throws \Exception
     */
    public function testRecordsATransition(): void
    {
        $this->repository->record(
            self::CREDENTIAL_ID_HASH,
            self::LIST_ID,
            42,
            StatusTypeEnum::Valid->value,
            StatusTypeEnum::Invalid->value,
            StatusChangeSourceEnum::Api,
            'HR system',
        );

        $rows = $this->readRows();

        $this->assertCount(1, $rows);
        $this->assertSame(self::CREDENTIAL_ID_HASH, $rows[0]['credential_id_hash']);
        $this->assertSame(self::LIST_ID, $rows[0]['status_list_id']);
        $this->assertSame(42, (int)$rows[0]['idx']);
        $this->assertSame(StatusTypeEnum::Valid->value, (int)$rows[0]['old_status']);
        $this->assertSame(StatusTypeEnum::Invalid->value, (int)$rows[0]['new_status']);
        $this->assertSame('HR system', $rows[0]['actor_ref']);
        $this->assertSame(StatusChangeSourceEnum::Api->value, $rows[0]['source']);
    }


    /**
     * A trail whose rows overwrite each other is not a trail. Every change against the same credential
     * has to survive alongside the ones before it.
     *
     * @throws \Exception
     */
    public function testKeepsEveryTransitionForTheSameCredential(): void
    {
        $this->repository->record(
            self::CREDENTIAL_ID_HASH,
            self::LIST_ID,
            42,
            StatusTypeEnum::Valid->value,
            StatusTypeEnum::Suspended->value,
            StatusChangeSourceEnum::Admin,
            'admin',
        );
        $this->repository->record(
            self::CREDENTIAL_ID_HASH,
            self::LIST_ID,
            42,
            StatusTypeEnum::Suspended->value,
            StatusTypeEnum::Invalid->value,
            StatusChangeSourceEnum::Api,
            'HR system',
        );

        $rows = $this->readRows();

        $this->assertCount(2, $rows);
        $this->assertNotSame($rows[0]['id'], $rows[1]['id']);
    }


    /**
     * A scheduled task has no human or API principal behind it, and inventing one would be worse than
     * recording that there was none.
     *
     * @throws \Exception
     */
    public function testRecordsAnUnattendedChangeWithNoActor(): void
    {
        $this->repository->record(
            self::CREDENTIAL_ID_HASH,
            self::LIST_ID,
            1,
            StatusTypeEnum::Valid->value,
            StatusTypeEnum::Invalid->value,
            StatusChangeSourceEnum::Cron,
        );

        $this->assertNull($this->readRows()[0]['actor_ref']);
    }


    /**
     * @throws \Exception
     */
    public function testStoresTheMomentInUtc(): void
    {
        $createdAt = new DateTimeImmutable('2026-08-07 12:00:00', new DateTimeZone('Europe/Zagreb'));

        $this->repository->record(
            self::CREDENTIAL_ID_HASH,
            self::LIST_ID,
            1,
            StatusTypeEnum::Valid->value,
            StatusTypeEnum::Invalid->value,
            StatusChangeSourceEnum::Api,
            'HR system',
            $createdAt,
        );

        $this->assertSame(
            $createdAt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
            $this->readRows()[0]['created_at'],
        );
    }


    /**
     * Every row needs its own identifier, and they are generated rather than handed out by the
     * database, so a collision would silently replace an earlier record of a change.
     *
     * @throws \Exception
     */
    public function testGivesEachRowADistinctIdentifier(): void
    {
        for ($i = 0; $i < 25; $i++) {
            $this->repository->record(
                self::CREDENTIAL_ID_HASH,
                self::LIST_ID,
                $i,
                StatusTypeEnum::Valid->value,
                StatusTypeEnum::Invalid->value,
                StatusChangeSourceEnum::Api,
                'HR system',
            );
        }

        $identifiers = array_column($this->readRows(), 'id');

        $this->assertCount(25, $identifiers);
        $this->assertSame($identifiers, array_unique($identifiers));
    }


    /**
     * @throws \Exception
     */
    protected function recordAt(string $createdAt, int $idx = 0): void
    {
        $this->repository->record(
            self::CREDENTIAL_ID_HASH,
            self::LIST_ID,
            $idx,
            StatusTypeEnum::Valid->value,
            StatusTypeEnum::Invalid->value,
            StatusChangeSourceEnum::Api,
            'HR system',
            new DateTimeImmutable($createdAt, new DateTimeZone('UTC')),
        );
    }


    /**
     * @throws \Exception
     */
    public function testRemovesRowsOlderThanTheCutOff(): void
    {
        $this->recordAt('2025-01-01 09:00:00', 1);
        $this->recordAt('2026-08-01 09:00:00', 2);

        $removed = $this->repository->removeOlderThan(
            new DateTimeImmutable('2026-01-01 00:00:00', new DateTimeZone('UTC')),
            10,
        );

        $this->assertSame(1, $removed);

        $rows = $this->readRows();

        $this->assertCount(1, $rows);
        $this->assertSame(2, (int)$rows[0]['idx']);
    }


    /**
     * @throws \Exception
     */
    public function testRemovesNoMoreThanTheGivenNumberOfRows(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->recordAt('2025-01-01 09:00:00', $i);
        }

        $cutOff = new DateTimeImmutable('2026-01-01 00:00:00', new DateTimeZone('UTC'));

        $this->assertSame(2, $this->repository->removeOlderThan($cutOff, 2));
        $this->assertSame(2, $this->repository->removeOlderThan($cutOff, 2));
        $this->assertSame(1, $this->repository->removeOlderThan($cutOff, 2));
        $this->assertSame(0, $this->repository->removeOlderThan($cutOff, 2));
    }


    /**
     * @throws \Exception
     */
    public function testRemovesNothingWhenEveryRowIsWithinRetention(): void
    {
        $this->recordAt('2026-08-01 09:00:00');

        $removed = $this->repository->removeOlderThan(
            new DateTimeImmutable('2026-01-01 00:00:00', new DateTimeZone('UTC')),
            10,
        );

        $this->assertSame(0, $removed);
        $this->assertCount(1, $this->readRows());
    }


    /**
     * The cut-off is compared against a column which carries no timezone and is written in UTC, so one
     * handed in on another scale would prune either too much or too little by the size of the offset.
     *
     * @throws \Exception
     */
    public function testComparesTheCutOffInUtc(): void
    {
        $this->recordAt('2026-08-07 10:00:00');

        // 11:00 in a zone two hours ahead is 09:00 UTC, which is before the row was written.
        $removed = $this->repository->removeOlderThan(
            new DateTimeImmutable('2026-08-07 11:00:00', new DateTimeZone('Europe/Zagreb')),
            10,
        );

        $this->assertSame(0, $removed);
        $this->assertCount(1, $this->readRows());
    }


    /**
     * The tests above run against a real SQLite, which has allowed 32766 bound variables since 3.32, so
     * a delete naming more identifiers than an older build accepts passes there regardless. Counting
     * what each statement binds is what shows the limit a deployment's own driver might impose.
     *
     * @throws \Exception
     */
    public function testRemovesInStatementsEveryDriverAccepts(): void
    {
        $selected = [];

        for ($id = 0; $id < 2500; $id++) {
            $selected[] = ['id' => 'audit-' . $id];
        }

        $bindings = [];

        $databaseMock = $this->createMock(Database::class);
        $databaseMock->method('applyPrefix')->willReturnCallback(
            static fn(string $table): string => 'phpunit_' . $table,
        );

        $statementMock = $this->createMock(PDOStatement::class);
        $statementMock->method('fetchAll')->willReturn($selected);
        $databaseMock->method('readPrimary')->willReturn($statementMock);

        // Answering with the row count of each statement rather than of the whole call, so a method
        // returning only its last statement's total would be caught here.
        $databaseMock->method('write')->willReturnCallback(
            /**
             * @param array<string,mixed> $params
             */
            function (string $statement, array $params = []) use (&$bindings): int {
                $bindings[] = $params;

                return count($params);
            },
        );

        $repository = new StatusAuditRepository($this->moduleConfigMock, $databaseMock, null, $this->helpers);

        $removed = $repository->removeOlderThan(
            new DateTimeImmutable('2026-01-01 00:00:00', new DateTimeZone('UTC')),
            2500,
        );

        $this->assertSame(2500, $removed);
        $this->assertGreaterThan(1, count($bindings));

        $named = [];

        foreach ($bindings as $params) {
            $this->assertLessThanOrEqual(self::MAX_BOUND_VARIABLES, count($params));

            foreach ($params as $value) {
                $named[] = $value;
            }
        }

        // Splitting the deletion across statements must remove exactly the rows which were selected,
        // neither leaving one behind nor naming one twice.
        $this->assertSame(array_column($selected, 'id'), $named);
    }
}

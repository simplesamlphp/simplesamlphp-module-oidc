<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateTimeImmutable;
use DateTimeZone;
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
class StatusAuditRepositoryTest extends TestCase
{
    protected const string CREDENTIAL_ID_HASH = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    protected const string LIST_ID = 'a-status-list-id';

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
}

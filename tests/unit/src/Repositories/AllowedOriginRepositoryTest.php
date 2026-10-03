<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository
 */
#[AllowMockObjectsWithoutExpectations]
class AllowedOriginRepositoryTest extends TestCase
{
    use LaggingSecondaryTestTrait;


    final public const string CLIENT_ID = 'some_client_id';

    final public const array ORIGINS = [
        'https://example.org',
        'https://sample.com',
    ];


    protected MockObject $moduleConfigMock;

    protected MockObject $protocolCacheMock;

    private AllowedOriginRepository $repository;


    /**
     * @throws \Exception
     */
    public static function setUpBeforeClass(): void
    {
        $config = [
            'database.dsn' => 'sqlite::memory:',
            'database.username' => null,
            'database.password' => null,
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.secondaries' => [],
        ];

        Configuration::loadFromArray($config, '', 'simplesaml');
        (new DatabaseMigration())->migrate();
    }


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->protocolCacheMock = $this->createMock(ProtocolCache::class);

        $database = Database::getInstance();

        $this->repository = new AllowedOriginRepository(
            $this->moduleConfigMock,
            $database,
            $this->protocolCacheMock,
        );
    }


    public function tearDown(): void
    {
        $this->repository->delete(self::CLIENT_ID);
    }


    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_allowed_origin', $this->repository->getTableName());
    }


    public function testSetGetHasDelete(): void
    {
        $this->repository->set(self::CLIENT_ID, []);
        $this->assertSame([], $this->repository->get(self::CLIENT_ID));

        $this->repository->set(self::CLIENT_ID, self::ORIGINS);
        $this->assertSame(self::ORIGINS, $this->repository->get(self::CLIENT_ID));
        $this->assertTrue($this->repository->has(self::ORIGINS[0]));
        $this->assertTrue($this->repository->has(self::ORIGINS[1]));
        $this->assertFalse($this->repository->has('https://invalid.org'));

        $this->repository->delete(self::CLIENT_ID);
        $this->assertFalse($this->repository->has(self::ORIGINS[0]));
        $this->assertFalse($this->repository->has(self::ORIGINS[1]));
    }


    public function testHasCanReturnFromCache(): void
    {
        $this->protocolCacheMock->expects($this->once())->method('get')
        ->willReturn(true);

        $this->assertTrue($this->repository->has('origin'));
    }


    /**
     * A browser client may make a CORS request as soon as an administrator allowed its origin, before a database
     * secondary may have it, and with no answer in a protocol cache (none is configured by default).
     */
    public function testAllowsAnOriginJustSetBeforeASecondaryHasIt(): void
    {
        $repository = $this->uncachedRepositoryOver($this->databaseWithALaggingSecondary());
        $repository->set(self::CLIENT_ID, ['https://just-allowed.example.org']);

        $this->assertTrue($repository->has('https://just-allowed.example.org'));
    }


    /**
     * An origin removed from a client is to be refused from then on, which a database secondary may not know yet. The
     * origin is looked up on the primary, and not only when a secondary has no row for it.
     */
    public function testRefusesAnOriginJustRemovedWhileASecondaryStillHasIt(): void
    {
        $this->repository->set(self::CLIENT_ID, ['https://just-removed.example.org']);
        $this->repository->set(self::CLIENT_ID, ['https://still-allowed.example.org']);

        // Both queries here fetch the origin column, so a stale secondary answers with the origins as they were.
        $repository = $this->uncachedRepositoryOver(
            $this->databaseWithAStaleSecondary(['https://just-removed.example.org']),
        );

        $this->assertFalse($repository->has('https://just-removed.example.org'));
    }


    /**
     * The administrator's client form is filled in with the origins read here, and saving it writes them back, which
     * would undo a change of them that a database secondary does not have yet.
     */
    public function testListsTheOriginsJustSetWhileASecondaryStillHasTheOldOnes(): void
    {
        $this->repository->set(self::CLIENT_ID, ['https://set-before.example.org']);
        $this->repository->set(self::CLIENT_ID, ['https://set-after.example.org']);

        $repository = $this->uncachedRepositoryOver(
            $this->databaseWithAStaleSecondary(['https://set-before.example.org']),
        );

        $this->assertSame(['https://set-after.example.org'], $repository->get(self::CLIENT_ID));
    }


    protected function uncachedRepositoryOver(Database $database): AllowedOriginRepository
    {
        return new AllowedOriginRepository($this->moduleConfigMock, $database, null);
    }
}

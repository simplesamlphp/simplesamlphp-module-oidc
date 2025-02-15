<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

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
class AllowedOriginRepositoryTest extends TestCase
{
    final public const CLIENT_ID = 'some_client_id';

    protected MockObject $moduleConfigMock;
    protected MockObject $protocolCacheMock;


    final public const ORIGINS = [
        'https://example.org',
        'https://sample.com',
    ];

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
}

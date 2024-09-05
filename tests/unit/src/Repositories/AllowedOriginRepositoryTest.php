<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository
 */
class AllowedOriginRepositoryTest extends TestCase
{
    final public const CLIENT_ID = 'some_client_id';

    final public const ORIGINS = [
        'https://example.org',
        'https://sample.com',
    ];

    private static AllowedOriginRepository $repository;

    private static ModuleConfig $moduleConfig;

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

        self::$moduleConfig = new ModuleConfig();

        $client = ClientRepositoryTest::getClient(self::CLIENT_ID);
        (new ClientRepository(self::$moduleConfig))->add($client);

        self::$repository = new AllowedOriginRepository(self::$moduleConfig);
    }

    public function tearDown(): void
    {
        self::$repository->delete(self::CLIENT_ID);
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_allowed_origin', self::$repository->getTableName());
    }

    public function testSetGetHasDelete(): void
    {
        self::$repository->set(self::CLIENT_ID, []);
        $this->assertSame([], self::$repository->get(self::CLIENT_ID));

        self::$repository->set(self::CLIENT_ID, self::ORIGINS);
        $this->assertSame(self::ORIGINS, self::$repository->get(self::CLIENT_ID));
        $this->assertTrue(self::$repository->has(self::ORIGINS[0]));
        $this->assertTrue(self::$repository->has(self::ORIGINS[1]));
        $this->assertFalse(self::$repository->has('https://invalid.org'));

        self::$repository->delete(self::CLIENT_ID);
        $this->assertFalse(self::$repository->has(self::ORIGINS[0]));
        $this->assertFalse(self::$repository->has(self::ORIGINS[1]));
    }
}

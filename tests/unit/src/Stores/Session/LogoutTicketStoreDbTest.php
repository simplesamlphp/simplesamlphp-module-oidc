<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Stores\Session;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreDb;

/**
 * @covers \SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreDb
 */
class LogoutTicketStoreDbTest extends TestCase
{
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

    /**
     * @throws \Exception
     */
    public function testCanAddAndDeleteTickets(): void
    {
        $store = new LogoutTicketStoreDb();
        $sid = 'sid123';
        $store->add($sid);
        $allSids = $store->getAll();
        $this->assertNotEmpty($allSids);
        $this->assertSame($sid, $allSids[0]['sid']);

        $store->delete($sid);

        $this->assertEmpty($store->getAll());
    }

    /**
     * @throws \Exception
     */
    public function testCanDeleteMultipleTickets(): void
    {
        $sid1 = 'sid1';
        $sid2 = 'sid2';
        $sid3 = 'sid3';

        $store = new LogoutTicketStoreDb();
        $store->add($sid1);
        $store->add($sid2);
        $store->add($sid3);

        $this->assertSame(3, count($store->getAll()));

        $store->deleteMultiple([]);

        $this->assertSame(3, count($store->getAll()));

        $store->deleteMultiple([$sid1, $sid2]);

        $this->assertSame(1, count($store->getAll()));

        $store->delete($sid3);

        $this->assertEmpty($store->getAll());
    }

    /**
     * @throws \Exception
     */
    public function testCanDeleteExpiredTickets(): void
    {
        $store = new LogoutTicketStoreDb(null, 0);
        $sid = 'sid123';
        $store->add($sid);
        $this->assertEmpty($store->getAll());
    }
}

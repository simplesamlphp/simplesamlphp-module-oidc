<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Stores\unit\Session;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreBuilder;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreInterface;

/**
 * @covers \SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreBuilder
 */
class LogoutTicketStoreBuilderTest extends TestCase
{
    public function testConstructWithDefaultStore(): void
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
        $builder = new LogoutTicketStoreBuilder();

        $this->assertInstanceOf(LogoutTicketStoreInterface::class, $builder->getInstance());
        $this->assertInstanceOf(LogoutTicketStoreInterface::class, $builder::getStaticInstance());
    }
}

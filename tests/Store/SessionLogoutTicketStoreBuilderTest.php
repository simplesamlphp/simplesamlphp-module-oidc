<?php

namespace SimpleSAML\Test\Module\oidc\Store;

use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Store\SessionLogoutTicketStoreBuilder;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Store\SessionLogoutTicketStoreInterface;

/**
 * @covers \SimpleSAML\Module\oidc\Store\SessionLogoutTicketStoreBuilder
 */
class SessionLogoutTicketStoreBuilderTest extends TestCase
{
    public function testConstructWithDefaultStore(): void
    {
        $config = [
            'database.dsn' => 'sqlite::memory:',
            'database.username' => null,
            'database.password' => null,
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.slaves' => [],
        ];

        Configuration::loadFromArray($config, '', 'simplesaml');
        $builder = new SessionLogoutTicketStoreBuilder();

        $this->assertInstanceOf(SessionLogoutTicketStoreInterface::class, $builder->getInstance());
        $this->assertInstanceOf(SessionLogoutTicketStoreInterface::class, $builder::getStaticInstance());
    }
}

<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Test\Module\oidc\Repositories;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

class UserRepositoryTest extends TestCase
{
    /**
     * @var UserRepository
     */
    protected static $repository;

    protected function setUp(): void
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
        (new DatabaseMigration())->migrate();

        $configurationService = new ConfigurationService();

        self::$repository = new UserRepository($configurationService);
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_user', self::$repository->getTableName());
    }

    public function testAddAndFound(): void
    {
        self::$repository->add(UserEntity::fromData('uniqueid'));
        $user = self::$repository->getUserEntityByIdentifier('uniqueid');

        $this->assertNotNull($user);
        /** @psalm-suppress PossiblyNullReference */
        $this->assertSame($user->getIdentifier(), 'uniqueid');
    }

    public function testNotFound(): void
    {
        $user = self::$repository->getUserEntityByIdentifier('unknownid');

        $this->assertNull($user);
    }

    public function testUpdate(): void
    {
        $user = self::$repository->getUserEntityByIdentifier('uniqueid');
        /** @psalm-suppress PossiblyNullReference */
        $user->setClaims(['uid' => ['johndoe']]);
        self::$repository->update($user);

        $user2 = self::$repository->getUserEntityByIdentifier('uniqueid');
        $this->assertNotSame($user, $user2);
    }

    public function testDelete(): void
    {
        $user = self::$repository->getUserEntityByIdentifier('uniqueid');
        /** @psalm-suppress PossiblyNullArgument */
        self::$repository->delete($user);
        $user = self::$repository->getUserEntityByIdentifier('uniqueid');

        $this->assertNull($user);
    }
}

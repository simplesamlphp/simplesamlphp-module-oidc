<?php

declare(strict_types=1);

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

use Exception;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\UserRepository
 */
class UserRepositoryTest extends TestCase
{
    protected static UserRepository $repository;

    /**
     * @throws Exception
     */
    protected function setUp(): void
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

        $moduleConfig = new ModuleConfig();

        self::$repository = new UserRepository($moduleConfig);
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_user', self::$repository->getTableName());
    }

    /**
     * @throws OidcServerException
     * @throws Exception
     */
    public function testAddAndFound(): void
    {
        self::$repository->add(UserEntity::fromData('uniqueid'));
        $user = self::$repository->getUserEntityByIdentifier('uniqueid');

        $this->assertNotNull($user);
        $this->assertSame($user->getIdentifier(), 'uniqueid');
    }

    /**
     * @throws OidcServerException
     */
    public function testNotFound(): void
    {
        $user = self::$repository->getUserEntityByIdentifier('unknownid');

        $this->assertNull($user);
    }

    /**
     * @throws OidcServerException
     * @throws Exception
     */
    public function testUpdate(): void
    {
        $user = self::$repository->getUserEntityByIdentifier('uniqueid');
        $user->setClaims(['uid' => ['johndoe']]);
        self::$repository->update($user);

        $user2 = self::$repository->getUserEntityByIdentifier('uniqueid');
        $this->assertNotSame($user, $user2);
    }

    /**
     * @throws OidcServerException
     */
    public function testDelete(): void
    {
        $user = self::$repository->getUserEntityByIdentifier('uniqueid');
        self::$repository->delete($user);
        $user = self::$repository->getUserEntityByIdentifier('uniqueid');

        $this->assertNull($user);
    }
}

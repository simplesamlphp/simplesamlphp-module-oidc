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
namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateTimeImmutable;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\UserRepository
 */
class UserRepositoryTest extends TestCase
{
    protected static UserRepository $repository;
    protected Stub $helpersStub;
    protected MockObject $userEntityFactoryMock;
    protected MockObject $userEntityMock;

    /**
     * @throws \Exception
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
        $this->helpersStub = $this->createStub(Helpers::class);
        $this->userEntityFactoryMock = $this->createMock(UserEntityFactory::class);
        $this->userEntityMock = $this->createMock(UserEntity::class);

        $database = Database::getInstance();

        self::$repository = new UserRepository(
            $moduleConfig,
            $database,
            null,
            $this->helpersStub,
            $this->userEntityFactoryMock,
        );
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_user', self::$repository->getTableName());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCanAddFindDelete(): void
    {
        $createdUpdatedAt = new DateTimeImmutable();
        self::$repository->add(new UserEntity('uniqueid', $createdUpdatedAt, $createdUpdatedAt));

        $this->userEntityMock->method('getIdentifier')->willReturn('uniqueid');
        $this->userEntityFactoryMock->expects($this->once())
            ->method('fromState')
            ->with($this->callback(function (array $state) {
                return $state['id'] === 'uniqueid';
            }))
        ->willReturn($this->userEntityMock);
        $user = self::$repository->getUserEntityByIdentifier('uniqueid');

        $this->assertNotNull($user);
        $this->assertSame($user->getIdentifier(), 'uniqueid');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testNotFound(): void
    {
        $user = self::$repository->getUserEntityByIdentifier('unknownid');

        $this->assertNull($user);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testUpdate(): void
    {
        $user = self::$repository->getUserEntityByIdentifier('uniqueid');
        $user->setClaims(['uid' => ['johndoe']]);
        self::$repository->update($user);

        $user2 = self::$repository->getUserEntityByIdentifier('uniqueid');
        $this->assertNotSame($user, $user2);
    }

    public function testCanDelete(): void
    {
        $this->userEntityMock->method('getIdentifier')->willReturn('uniqueid');
        $this->assertNotNull(self::$repository->getUserEntityByIdentifier('uniqueid'));
        self::$repository->delete($this->userEntityMock);
        $this->assertNull(self::$repository->getUserEntityByIdentifier('uniqueid'));
    }
}

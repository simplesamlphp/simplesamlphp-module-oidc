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
use PDOStatement;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\UserRepository
 */
class UserRepositoryTest extends TestCase
{
    protected static UserRepository $repository;
    protected Stub $helpersStub;
    protected MockObject $userEntityFactoryMock;
    protected MockObject $userEntityMock;
    protected MockObject $moduleConfigMock;
    protected ?MockObject $protocolCacheMock;
    protected MockObject $databaseMock;
    protected MockObject $pdoStatementMock;
    protected Database $database;
    protected array $userEntityState = [
        'id' => 'uniqueid',
        'claims' => '[]',
        'updated_at' => '2024-11-04 11:07:26',
        'created_at' => '2024-11-04 11:07:26',
    ];

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
        $this->database = Database::getInstance();
        (new DatabaseMigration($this->database))->migrate();

        $this->databaseMock = $this->createMock(Database::class);
        $this->pdoStatementMock = $this->createMock(PDOStatement::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->helpersStub = $this->createStub(Helpers::class);
        $this->userEntityFactoryMock = $this->createMock(UserEntityFactory::class);
        $this->userEntityMock = $this->createMock(UserEntity::class);
        $this->protocolCacheMock = $this->createMock(ProtocolCache::class);
    }

    protected function mock(
        ?ModuleConfig $moduleConfig = null,
        ?Database $database = null,
        ?ProtocolCache $protocolCache = null,
        ?Helpers $helpers = null,
        ?UserEntityFactory $userEntityFactory = null,
    ): UserRepository {
        $moduleConfig ??= $this->moduleConfigMock;
        $database ??= $this->database; // Let's use real database instance for tests by default.
        $protocolCache ??= null; // Let's not use cache for tests by default.
        $helpers ??= $this->helpersStub;
        $userEntityFactory ??= $this->userEntityFactoryMock;

        return new UserRepository(
            $moduleConfig,
            $database,
            $protocolCache,
            $helpers,
            $userEntityFactory,
        );
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_user', $this->mock()->getTableName());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCanAddFindDelete(): void
    {
        $repository = $this->mock();

        $createdUpdatedAt = new DateTimeImmutable();
        $userEntity = new UserEntity('uniqueid', $createdUpdatedAt, $createdUpdatedAt);

        $repository->add($userEntity);

        $this->userEntityFactoryMock->expects($this->once())
            ->method('fromState')
            ->with($this->callback(function (array $state) {
                return $state['id'] === 'uniqueid';
            }))
        ->willReturn($userEntity);

        $user = $repository->getUserEntityByIdentifier('uniqueid');

        $this->assertNotNull($user);
        $this->assertSame($user->getIdentifier(), 'uniqueid');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testNotFound(): void
    {
        $user = $this->mock()->getUserEntityByIdentifier('unknownid');

        $this->assertNull($user);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testUpdate(): void
    {
        $repository = $this->mock();

        $user = $repository->getUserEntityByIdentifier('uniqueid');
        $user->setClaims(['uid' => ['johndoe']]);
        $repository->update($user);

        $user2 = $repository->getUserEntityByIdentifier('uniqueid');
        $this->assertNotSame($user, $user2);
    }

    public function testCanDelete(): void
    {
        $repository = $this->mock();

        $this->userEntityMock->method('getIdentifier')->willReturn('uniqueid');
        $this->assertNotNull($repository->getUserEntityByIdentifier('uniqueid'));
        $repository->delete($this->userEntityMock);
        $this->assertNull($repository->getUserEntityByIdentifier('uniqueid'));
    }

    public function testCanGetWhenUserEntityIsCached(): void
    {
        $this->protocolCacheMock->expects($this->once())
            ->method('get')
            ->willReturn($this->userEntityState);

        $this->databaseMock->expects($this->never())->method('read');

        $this->userEntityFactoryMock->expects($this->once())
            ->method('fromState')
            ->with($this->callback(function (array $state) {
                return $state['id'] === 'uniqueid';
            }))
            ->willReturn($this->userEntityMock);

        $repository = $this->mock(
            database: $this->databaseMock,
            protocolCache: $this->protocolCacheMock,
        );

        $this->assertSame(
            $this->userEntityMock,
            $repository->getUserEntityByIdentifier('uniqueid'),
        );
    }

    public function testCanGetWhenUserEntityIsNotCached(): void
    {
        $this->protocolCacheMock->expects($this->once())
            ->method('get')
            ->willReturn(null);

        $this->protocolCacheMock->expects($this->once())
            ->method('set')
            ->with($this->userEntityState);

        $this->pdoStatementMock->method('fetchAll')->willReturn([$this->userEntityState]);

        $this->databaseMock->expects($this->once())
            ->method('read')
            ->willReturn($this->pdoStatementMock);

        $this->userEntityMock->expects($this->once())
            ->method('getState')
            ->willReturn($this->userEntityState);

        $this->userEntityFactoryMock->expects($this->once())
            ->method('fromState')
            ->with($this->callback(function (array $state) {
                return $state['id'] === 'uniqueid';
            }))
            ->willReturn($this->userEntityMock);

        $repository = $this->mock(
            database: $this->databaseMock,
            protocolCache: $this->protocolCacheMock,
        );

        $this->assertSame(
            $this->userEntityMock,
            $repository->getUserEntityByIdentifier('uniqueid'),
        );
    }

    public function testWillAddToDatabaseAndCache(): void
    {
        $this->moduleConfigMock->method('getProtocolUserEntityCacheDuration')
            ->willReturn(new \DateInterval('PT1H'));

        $this->userEntityMock->expects($this->exactly(2))
            ->method('getState')
            ->willReturn($this->userEntityState);

        $this->protocolCacheMock->expects($this->once())
            ->method('set')
            ->with($this->userEntityState);

        $this->databaseMock->expects($this->once())
            ->method('write')
            ->with(
                $this->isType('string'),
                $this->userEntityState,
            );

        $this->mock(
            database: $this->databaseMock,
            protocolCache: $this->protocolCacheMock,
        )->add($this->userEntityMock);
    }

    public function testWillUpdateDatabaseAndCache(): void
    {
        $this->moduleConfigMock->method('getProtocolUserEntityCacheDuration')
            ->willReturn(new \DateInterval('PT1H'));

        $this->userEntityMock->expects($this->exactly(2))
            ->method('getState')
            ->willReturn($this->userEntityState);

        $this->protocolCacheMock->expects($this->once())
            ->method('set')
            ->with($this->userEntityState);

        $this->databaseMock->expects($this->once())
            ->method('write')
            ->with(
                $this->isType('string'),
                $this->userEntityState,
            );

        $this->mock(
            database: $this->databaseMock,
            protocolCache: $this->protocolCacheMock,
        )->update($this->userEntityMock);
    }

    public function testWillDeleteFromDatabaseAndCache(): void
    {
        $this->userEntityMock->expects($this->exactly(2))
            ->method('getIdentifier')
            ->willReturn('uniqueid');

        $this->protocolCacheMock->expects($this->once())
            ->method('delete')
            ->with($this->stringContains('uniqueid'));

        $this->databaseMock->expects($this->once())
            ->method('write')
            ->with(
                $this->stringContains('DELETE'),
                $this->callback(function (array $params) {
                    return $params['id'] === 'uniqueid';
                }),
            );

        $this->mock(
            database: $this->databaseMock,
            protocolCache: $this->protocolCacheMock,
        )->delete($this->userEntityMock);
    }

    public function testGetUserEntityByUserCredentialsThrows(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Not supported');

        $this->mock()->getUserEntityByUserCredentials(
            'username',
            'password',
            'grantType',
            $this->createMock(ClientEntityInterface::class),
        );
    }
}

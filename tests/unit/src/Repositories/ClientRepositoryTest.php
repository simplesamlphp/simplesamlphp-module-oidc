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

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\ClientRepository
 */
class ClientRepositoryTest extends TestCase
{
    protected ClientRepository $repository;
    protected MockObject $clientEntityMock;
    protected MockObject $clientEntityFactoryMock;

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
        $this->clientEntityMock = $this->createMock(ClientEntityInterface::class);
        $this->clientEntityFactoryMock = $this->createMock(ClientEntityFactory::class);

        $database = Database::getInstance();

        $this->repository = new ClientRepository(
            new ModuleConfig(),
            $database,
            null,
            $this->clientEntityFactoryMock,
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function tearDown(): void
    {
        $this->clientEntityFactoryMock->method('fromState')->willReturnCallback(
            function (array $state) {
                $client = $this->createStub(ClientEntityInterface::class);
                $client->method('getIdentifier')->willReturn($state['id']);
                return $client;
            },
        );

        $clients = $this->repository->findAll();

        foreach ($clients as $client) {
            $this->repository->delete($client);
        }
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_client', $this->repository->getTableName());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testAddAndFound(): void
    {
        $client = self::getClient('clientid');
        $this->repository->add($client);
        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')->willReturn($client);
        $foundClient = $this->repository->findById('clientid');
        $this->assertEquals($client, $foundClient);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testGetClientEntity(): void
    {
        $client = self::getClient('clientid');
        $this->repository->add($client);
        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')->willReturn($client);
        $client = $this->repository->getClientEntity('clientid');
        $this->assertNotNull($client);
    }

    public function testGetClientEntityReturnsNullForExpiredClient(): void
    {
        $this->clientEntityMock->expects($this->once())->method('isExpired')->willReturn(true);

        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')
            ->willReturn($this->clientEntityMock);

        // Just so we have a client with this ID in repo.
        $client = self::getClient('clientid');
        $this->repository->add($client);

        $this->assertNull($this->repository->getClientEntity('clientid'));
    }

    /**
     * @throws \JsonException
     */
    public function testGetDisabledClientEntity(): void
    {
        $client = self::getClient('clientid', false);
        $this->repository->add($client);

        $this->assertNull($this->repository->getClientEntity('clientid'));
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testNotFoundClient(): void
    {
        $client = $this->repository->getClientEntity('unknownid');

        $this->assertNull($client);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testValidateConfidentialClient(): void
    {
        $client = self::getClient('clientid', true, true);
        $this->repository->add($client);

        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')->willReturn($client);

        $validate = $this->repository->validateClient('clientid', 'clientsecret', null);
        $this->assertTrue($validate);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testValidatePublicClient(): void
    {
        $client = self::getClient('clientid');
        $this->repository->add($client);

        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')->willReturn($client);

        $validate = $this->repository->validateClient('clientid', null, null);
        $this->assertTrue($validate);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testNotValidateConfidentialClientWithWrongSecret()
    {
        $client = self::getClient('clientid', true, true);
        $this->repository->add($client);

        $validate = $this->repository->validateClient('clientid', 'wrongclientsecret', null);
        $this->assertFalse($validate);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testNotValidateWhenClientDoesNotExists()
    {
        $validate = $this->repository->validateClient('clientid', 'wrongclientsecret', null);
        $this->assertFalse($validate);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testFindAll(): void
    {
        $client = self::getClient('clientid');
        $this->repository->add($client);
        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')->willReturn($client);
        $clients = $this->repository->findAll();
        $this->assertCount(1, $clients);
        $this->assertInstanceOf(ClientEntity::class, current($clients));
    }

    /**
     * @throws \Exception
     */
    public function testFindPaginated(): void
    {
        array_map(function ($i) {
            $this->repository->add(self::getClient('clientid' . $i));
        }, range(1, 21));

        $this->clientEntityFactoryMock->method('fromState')->willReturn($this->clientEntityMock);

        $clientPageOne = $this->repository->findPaginated();
        self::assertCount(20, $clientPageOne['items']);
        self::assertEquals(2, $clientPageOne['numPages']);
        self::assertEquals(1, $clientPageOne['currentPage']);
        $clientPageTwo = $this->repository->findPaginated(2);
        self::assertCount(1, $clientPageTwo['items']);
        self::assertEquals(2, $clientPageTwo['numPages']);
        self::assertEquals(2, $clientPageTwo['currentPage']);
    }

    /**
     * @throws \Exception
     */
    public function testFindPageInRange(): void
    {
        array_map(function ($i) {
            $this->repository->add(self::getClient('clientid' . $i));
        }, range(1, 21));

        $clientPageOne = $this->repository->findPaginated(0);
        self::assertEquals(1, $clientPageOne['currentPage']);
        $clientPageOne = $this->repository->findPaginated(3);
        self::assertEquals(2, $clientPageOne['currentPage']);
    }

    /**
     * @throws \Exception
     */
    public function testFindPaginationWithEmptyList()
    {
        $clientPageOne = $this->repository->findPaginated(0);
        self::assertEquals(1, $clientPageOne['numPages']);
        self::assertEquals(1, $clientPageOne['currentPage']);
        self::assertCount(0, $clientPageOne['items']);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testUpdate(): void
    {
        $client = self::getClient(id: 'clientId', entityId: 'entityId');
        $this->repository->add($client);

        $client = new ClientEntity(
            identifier: 'clientId',
            secret: 'newclientsecret',
            name: 'Client',
            description: 'Description',
            redirectUri: ['http://localhost/redirect'],
            scopes: ['openid'],
            isEnabled: true,
            isConfidential: false,
            authSource: 'admin',
            entityIdentifier: 'newEntityId',
        );

        $this->repository->update($client);
        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')->willReturn($client);
        $foundClient = $this->repository->findById('clientId');

        $this->assertEquals($client, $foundClient);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testDelete(): void
    {
        $client = self::getClient(id: 'clientId', entityId: 'entityId');
        $this->repository->add($client);

        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')->willReturn($client);
        $client = $this->repository->findById('clientId');
        $this->repository->delete($client);
        $foundClient = $this->repository->findById('clientId');

        $this->assertNull($foundClient);
    }

    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testCrudWithOwner(): void
    {
        $owner = 'homer@example.com';
        $ownedClientId = 'clientid';
        $unownedClientId = 'otherClientId';
        $ownedClient =  self::getClient($ownedClientId, true, false, $owner);
        $this->repository->add($ownedClient);

        $notOwnedClient =  self::getClient($unownedClientId, true, false, 'otherUser');
        $this->repository->add($notOwnedClient);
        // Owner can see their client but not others
        $this->assertNotNull($this->repository->findById($ownedClientId, $owner));
        $this->assertNull($this->repository->findById($unownedClientId, $owner));
        $this->assertNotNull($this->repository->findById($unownedClientId), 'Non owned should exist');

        // Owner can search for their client but not others
        $this->assertCount(1, $this->repository->findAll($owner));

        $this->clientEntityFactoryMock->method('fromState')->willReturn($this->clientEntityMock);
        // There are two clients with name 'Client' but the owner can only see theirs
        $this->assertCount(2, $this->repository->findPaginated(1, 'Client')['items']);
        $this->assertCount(1, $this->repository->findPaginated(1, 'Client', $owner)['items']);

        // Owner can update their own client
        $ownedClient =  self::getClient($ownedClientId, false, false, $owner);
        $this->repository->update($ownedClient, $owner);
        $foundClient = $this->repository->findById($ownedClientId, $owner);
        $this->assertNotNull($foundClient);
        $this->assertFalse($foundClient->isEnabled());

        // Owner can not update other clients
        $notOwnedClient =  self::getClient($unownedClientId, false, false, 'otherUser');
        $this->repository->update($notOwnedClient, $owner);
        $foundClient = $this->repository->findById($unownedClientId);
        $this->assertNotNull($foundClient);

        // Owner can delete their own client
        $this->repository->delete($ownedClient, $owner);
        $foundClient = $this->repository->findById($ownedClientId);
        $this->assertNull($foundClient);

        // Owner cannot delete unowned client
        $this->repository->delete($notOwnedClient, $owner);
        $foundClient = $this->repository->findById($unownedClientId);
        $this->assertNotNull($foundClient);
    }

    public function testCanFindByIdFromCache(): void
    {
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->expects($this->once())->method('get')->willReturn(['state']);


        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')
            ->with(['state'])
            ->willReturn($this->clientEntityMock);

        $sut = new ClientRepository(
            new ModuleConfig(),
            Database::getInstance(),
            $protocolCacheMock,
            $this->clientEntityFactoryMock,
        );

        $this->assertInstanceOf(ClientEntityInterface::class, $sut->findById('clientid'));
    }

    public function testCanFindByEntityIdentifier(): void
    {
        $client = self::getClient(id: 'clientId', entityId: 'entityId');
        $this->repository->add($client);

        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')->willReturn($client);

        $this->assertSame(
            $client,
            $this->repository->findByEntityIdentifier('entityId'),
        );

        $this->assertNull($this->repository->findByEntityIdentifier('nonExistingEntityId'));
    }

    public function testCanFindFederatedByEntityIdentifier(): void
    {
        $client = self::getClient(id: 'clientId', entityId: 'entityId', isFederated: true, federationJwks: []);
        $this->repository->add($client);

        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')->willReturn($client);

        $this->assertSame(
            $client,
            $this->repository->findFederatedByEntityIdentifier('entityId'),
        );

        $this->assertNull($this->repository->findFederatedByEntityIdentifier('nonExistingEntityId'));
    }

    public function testCanNotFindFederatedByEntityIdentifierIfMissingFederationAttributes(): void
    {
        $client = self::getClient(id: 'clientId', entityId: 'entityId');
        $this->repository->add($client);

        $this->clientEntityFactoryMock->expects($this->atLeastOnce())->method('fromState')->willReturn($client);

        $this->assertSame(
            $client,
            $this->repository->findByEntityIdentifier('entityId'),
        );

        $this->assertNull($this->repository->findFederatedByEntityIdentifier('entityId'));
    }

    public function testCanFindAllFederated(): void
    {
        $client = self::getClient(id: 'clientId', entityId: 'entityId', isFederated: true, federationJwks: []);
        $this->repository->add($client);

        $this->clientEntityFactoryMock->expects($this->atLeastOnce())->method('fromState')->willReturn($client);

        $this->assertCount(1, $this->repository->findAllFederated());
    }

    public function testCanFindByEntityIdFromCache(): void
    {
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->expects($this->once())->method('get')->willReturn(['state']);

        $this->clientEntityFactoryMock->expects($this->once())->method('fromState')
            ->with(['state'])
            ->willReturn($this->clientEntityMock);

        $sut = new ClientRepository(
            new ModuleConfig(),
            Database::getInstance(),
            $protocolCacheMock,
            $this->clientEntityFactoryMock,
        );

        $this->assertInstanceOf(ClientEntityInterface::class, $sut->findByEntityIdentifier('entityId'));
    }

    public static function getClient(
        string $id,
        bool $enabled = true,
        bool $confidential = false,
        ?string $owner = null,
        ?string $entityId = null,
        bool $isFederated = false,
        ?array $federationJwks = null,
    ): ClientEntityInterface {
        return new ClientEntity(
            identifier: $id,
            secret: 'clientsecret',
            name: 'Client',
            description: 'Description',
            redirectUri: ['http://localhost/redirect'],
            scopes: ['openid'],
            isEnabled: $enabled,
            isConfidential: $confidential,
            authSource: 'admin',
            owner: $owner,
            entityIdentifier: $entityId,
            federationJwks: $federationJwks,
            isFederated: $isFederated,
        );
    }
}

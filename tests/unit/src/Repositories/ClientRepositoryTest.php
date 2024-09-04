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

use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\ClientRepository
 */
class ClientRepositoryTest extends TestCase
{
    protected static ClientRepository $repository;

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

        $moduleConfig = new ModuleConfig();

        self::$repository = new ClientRepository($moduleConfig);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function tearDown(): void
    {
        $clients = self::$repository->findAll();

        foreach ($clients as $client) {
            self::$repository->delete($client);
        }
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_client', self::$repository->getTableName());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testAddAndFound(): void
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $foundClient = self::$repository->findById('clientid');
        $this->assertEquals($client, $foundClient);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testGetClientEntity(): void
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $client = self::$repository->getClientEntity('clientid');
        $this->assertNotNull($client);
    }

    /**
     * @throws \JsonException
     */
    public function testGetDisabledClientEntity(): void
    {
        $this->expectException(OAuthServerException::class);

        $client = self::getClient('clientid', false);
        self::$repository->add($client);

        self::$repository->getClientEntity('clientid');
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testNotFoundClient(): void
    {
        $client = self::$repository->getClientEntity('unknownid');

        $this->assertNull($client);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testValidateConfidentialClient(): void
    {
        $client = self::getClient('clientid', true, true);
        self::$repository->add($client);

        $validate = self::$repository->validateClient('clientid', 'clientsecret', null);
        $this->assertTrue($validate);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testValidatePublicClient(): void
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $validate = self::$repository->validateClient('clientid', null, null);
        $this->assertTrue($validate);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testNotValidateConfidentialClientWithWrongSecret()
    {
        $client = self::getClient('clientid', true, true);
        self::$repository->add($client);

        $validate = self::$repository->validateClient('clientid', 'wrongclientsecret', null);
        $this->assertFalse($validate);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \JsonException
     */
    public function testNotValidateWhenClientDoesNotExists()
    {
        $validate = self::$repository->validateClient('clientid', 'wrongclientsecret', null);
        $this->assertFalse($validate);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testFindAll(): void
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $clients = self::$repository->findAll();
        $this->assertCount(1, $clients);
        $this->assertInstanceOf(ClientEntity::class, current($clients));
    }

    /**
     * @throws \Exception
     */
    public function testFindPaginated(): void
    {
        array_map(function ($i) {
            self::$repository->add(self::getClient('clientid' . $i));
        }, range(1, 21));

        $clientPageOne = self::$repository->findPaginated();
        self::assertCount(20, $clientPageOne['items']);
        self::assertEquals(2, $clientPageOne['numPages']);
        self::assertEquals(1, $clientPageOne['currentPage']);
        $clientPageTwo = self::$repository->findPaginated(2);
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
            self::$repository->add(self::getClient('clientid' . $i));
        }, range(1, 21));

        $clientPageOne = self::$repository->findPaginated(0);
        self::assertEquals(1, $clientPageOne['currentPage']);
        $clientPageOne = self::$repository->findPaginated(3);
        self::assertEquals(2, $clientPageOne['currentPage']);
    }

    /**
     * @throws \Exception
     */
    public function testFindPaginationWithEmptyList()
    {
        $clientPageOne = self::$repository->findPaginated(0);
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
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $client = ClientEntity::fromData(
            'clientid',
            'newclientsecret',
            'Client',
            'Description',
            ['http://localhost/redirect'],
            ['openid'],
            true,
            false,
            'admin',
        );

        self::$repository->update($client);
        $foundClient = self::$repository->findById('clientid');

        $this->assertEquals($client, $foundClient);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testDelete(): void
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $client = self::$repository->findById('clientid');
        self::$repository->delete($client);
        $foundClient = self::$repository->findById('clientid');

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
        self::$repository->add($ownedClient);

        $notOwnedClient =  self::getClient($unownedClientId, true, false, 'otherUser');
        self::$repository->add($notOwnedClient);
        // Owner can see their client but not others
        $this->assertNotNull(self::$repository->findById($ownedClientId, $owner));
        $this->assertNull(self::$repository->findById($unownedClientId, $owner));
        $this->assertNotNull(self::$repository->findById($unownedClientId), 'Non owned should exist');

        // Owner can search for their client but not others
        $this->assertCount(1, self::$repository->findAll($owner));

        // There are two clients with name 'Client' but the owner can only see theirs
        $this->assertCount(2, self::$repository->findPaginated(1, 'Client')['items']);
        $this->assertCount(1, self::$repository->findPaginated(1, 'Client', $owner)['items']);

        // Owner can update their own client
        $ownedClient =  self::getClient($ownedClientId, false, false, $owner);
        self::$repository->update($ownedClient, $owner);
        $foundClient = self::$repository->findById($ownedClientId, $owner);
        $this->assertNotNull($foundClient);
        $this->assertFalse($foundClient->isEnabled());

        // Owner can not update other clients
        $notOwnedClient =  self::getClient($unownedClientId, false, false, 'otherUser');
        self::$repository->update($notOwnedClient, $owner);
        $foundClient = self::$repository->findById($unownedClientId);
        $this->assertNotNull($foundClient);
        $this->assertTrue($foundClient->isEnabled());

        // Owner can delete their own client
        self::$repository->delete($ownedClient, $owner);
        $foundClient = self::$repository->findById($ownedClientId);
        $this->assertNull($foundClient);

        // Owner cannot delete their own client
        self::$repository->delete($notOwnedClient, $owner);
        $foundClient = self::$repository->findById($unownedClientId);
        $this->assertNotNull($foundClient);
    }

    public static function getClient(
        string $id,
        bool $enabled = true,
        bool $confidential = false,
        ?string $owner = null,
    ): ClientEntityInterface {
        return ClientEntity::fromData(
            $id,
            'clientsecret',
            'Client',
            'Description',
            ['http://localhost/redirect'],
            ['openid'],
            $enabled,
            $confidential,
            'admin',
            $owner,
        );
    }
}

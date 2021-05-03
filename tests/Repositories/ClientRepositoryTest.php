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

namespace Tests\SimpleSAML\Modules\OpenIDConnect\Repositories;

use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;

class ClientRepositoryTest extends TestCase
{
    /**
     * @var ClientRepository
     */
    protected static $repository;

    public static function setUpBeforeClass(): void
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

        self::$repository = new ClientRepository($configurationService);
    }

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

    public function testAddAndFound(): void
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $foundClient = self::$repository->findById('clientid');
        $this->assertEquals($client, $foundClient);
    }

    public function testGetClientEntity(): void
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $client = self::$repository->getClientEntity('clientid');
        $this->assertNotNull($client);
    }

    public function testGetDisabledClientEntity(): void
    {
        $this->expectException(OAuthServerException::class);

        $client = self::getClient('clientid', false);
        self::$repository->add($client);

        $client = self::$repository->getClientEntity('clientid');
    }

    public function testNotFoundClient(): void
    {
        $client = self::$repository->getClientEntity('unknownid');

        $this->assertNull($client);
    }

    public function testValidateConfidentialClient(): void
    {
        $client = self::getClient('clientid', true, true);
        self::$repository->add($client);

        $validate = self::$repository->validateClient('clientid', 'clientsecret', null);
        $this->assertTrue($validate);
    }

    public function testValidatePublicClient(): void
    {
        $client = self::getClient('clientid', true);
        self::$repository->add($client);

        $validate = self::$repository->validateClient('clientid', null, null);
        $this->assertTrue($validate);
    }

    public function testNotValidateConfidentialClientWithWrongSecret()
    {
        $client = self::getClient('clientid', true, true);
        self::$repository->add($client);

        $validate = self::$repository->validateClient('clientid', 'wrongclientsecret', null);
        $this->assertFalse($validate);
    }

    public function testNotValidateWhenClientDoesNotExists()
    {
        $validate = self::$repository->validateClient('clientid', 'wrongclientsecret', null);
        $this->assertFalse($validate);
    }

    public function testFindAll(): void
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $clients = self::$repository->findAll();
        $this->assertCount(1, $clients);
        $this->assertInstanceOf(ClientEntity::class, current($clients));
    }

    public function testFindPaginated(): void
    {
        array_map(function ($i) {
            self::$repository->add(self::getClient('clientid' . $i));
        }, range(1, 21));

        $clientPageOne = self::$repository->findPaginated(1);
        self::assertCount(20, $clientPageOne['items']);
        self::assertEquals(2, $clientPageOne['numPages']);
        self::assertEquals(1, $clientPageOne['currentPage']);
        $clientPageTwo = self::$repository->findPaginated(2);
        self::assertCount(1, $clientPageTwo['items']);
        self::assertEquals(2, $clientPageTwo['numPages']);
        self::assertEquals(2, $clientPageTwo['currentPage']);
    }

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

    public function testFindPaginationWithEmptyList()
    {
        $clientPageOne = self::$repository->findPaginated(0);
        self::assertEquals(1, $clientPageOne['numPages']);
        self::assertEquals(1, $clientPageOne['currentPage']);
        self::assertCount(0, $clientPageOne['items']);
    }

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
            'admin'
        );

        self::$repository->update($client);
        $foundClient = self::$repository->findById('clientid');

        $this->assertEquals($client, $foundClient);
    }

    public function testDelete(): void
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $client = self::$repository->findById('clientid');
        /** @psalm-suppress PossiblyNullArgument */
        self::$repository->delete($client);
        $foundClient = self::$repository->findById('clientid');

        $this->assertNull($foundClient);
    }

    public static function getClient(string $id, bool $enabled = true, bool $confidential = false): ClientEntity
    {
        return ClientEntity::fromData(
            $id,
            'clientsecret',
            'Client',
            'Description',
            ['http://localhost/redirect'],
            ['openid'],
            $enabled,
            $confidential,
            'admin'
        );
    }
}

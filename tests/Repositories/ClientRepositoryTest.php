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

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;

class ClientRepositoryTest extends TestCase
{
    /**
     * @var ClientRepository
     */
    protected static $repository;

    public static function setUpBeforeClass()
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

        self::$repository = new ClientRepository();
    }

    public function tearDown()
    {
        $clients = self::$repository->findAll();

        foreach ($clients as $client) {
            self::$repository->delete($client);
        }
    }

    public function testGetTableName()
    {
        $this->assertSame('phpunit_oidc_client', self::$repository->getTableName());
    }

    public function testAddAndFound()
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $foundClient = self::$repository->findById('clientid');
        $this->assertEquals($client, $foundClient);
    }

    public function testGetClientEntityWithoutSecretAndFound()
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $client = self::$repository->getClientEntity('clientid', null, null, false);
        $this->assertNotNull($client);
    }

    public function testGetClientEntityWithSecretAndFound()
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $client = self::$repository->getClientEntity('clientid', null, 'clientsecret', true);
        $this->assertNotNull($client);
    }

    public function testGetDisabledClientEntity()
    {
        $client = self::getClient('clientid', false);
        self::$repository->add($client);

        $client = self::$repository->getClientEntity('clientid', null, 'wrongsecret', true);
        $this->assertNull($client);
    }

    public function testGetClientEntityWithWrongIdAndNotFound()
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $client = self::$repository->getClientEntity('wrongid', null, null, false);
        $this->assertNull($client);
    }

    public function testFindAll()
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $clients = self::$repository->findAll();
        $this->assertCount(1, $clients);
        $this->assertInstanceOf(ClientEntity::class, current($clients));
    }

    public function testUpdate()
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $client = ClientEntity::fromData(
            'clientid',
            'newclientsecret',
            'Client',
            'Description',
            'admin',
            ['http://localhost/redirect'],
            ['openid'],
            true
        );

        self::$repository->update($client);
        $foundClient = self::$repository->findById('clientid');

        $this->assertEquals($client, $foundClient);
    }

    public function testDelete()
    {
        $client = self::getClient('clientid');
        self::$repository->add($client);

        $client = self::$repository->findById('clientid');
        self::$repository->delete($client);
        $foundClient = self::$repository->findById('clientid');

        $this->assertNull($foundClient);
    }

    public static function getClient(string $id, bool $enabled = true)
    {
        return ClientEntity::fromData(
            $id,
            'clientsecret',
            'Client',
            'Description',
            'admin',
            ['http://localhost/redirect'],
            ['openid'],
            $enabled
        );
    }
}

<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Repositories;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;

class ClientRepositoryTest extends TestCase
{
    protected function setUp()
    {
        $config = [
            'database.dsn' => 'sqlite::memory:',
            'database.username' => null,
            'database.password' => null,
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.slaves' => [],
        ];

        \SimpleSAML_Configuration::loadFromArray($config, '', 'simplesaml');
        (new DatabaseMigration())->migrate();
    }

    public function testGetTableName()
    {
        $repository = new ClientRepository();

        $this->assertSame('phpunit_oidc_client', $repository->getTableName());
    }

    public function testAddAndFound()
    {
        $client = ClientEntity::fromData(
            'clientid',
            'clientsecret',
            'Client',
            'Description',
            'admin',
            ['http://localhost/redirect'],
            ['openid']
        );

        $repository = new ClientRepository();
        $repository->add($client);

        $foundClient = $repository->findById('clientid');
        $this->assertEquals($client, $foundClient);
    }

    public function testGetClientEntityWithoutSecretAndFound()
    {
        $repository = new ClientRepository();

        $client = $repository->getClientEntity('clientid', null, null, false);
        $this->assertNotNull($client);
    }

    public function testGetClientEntityWithSecretAndFound()
    {
        $repository = new ClientRepository();

        $client = $repository->getClientEntity('clientid', null, 'clientsecret', true);
        $this->assertNotNull($client);
    }

    public function testGetClientEntityWithWrongSecretAndNotFound()
    {
        $repository = new ClientRepository();

        $client = $repository->getClientEntity('clientid', null, 'wrongsecret', true);
        $this->assertNull($client);
    }

    public function testGetClientEntityWithWrongIdAndNotFound()
    {
        $repository = new ClientRepository();

        $client = $repository->getClientEntity('wrongid', null, null, false);
        $this->assertNull($client);
    }

    public function testFindAll()
    {
        $repository = new ClientRepository();

        $clients = $repository->findAll();
        $this->assertCount(1, $clients);
        $this->assertInstanceOf(ClientEntity::class, current($clients));
    }

    public function testUpdate()
    {
        $repository = new ClientRepository();

        $client = ClientEntity::fromData(
            'clientid',
            'newclientsecret',
            'Client',
            'Description',
            'admin',
            ['http://localhost/redirect'],
            ['openid']
        );

        $repository->update($client);
        $foundClient = $repository->findById('clientid');

        $this->assertEquals($client, $foundClient);
    }

    public function testDelete()
    {
        $repository = new ClientRepository();

        $client = $repository->findById('clientid');
        $repository->delete($client);
        $foundClient = $repository->findById('clientid');

        $this->assertNull($foundClient);
    }
}

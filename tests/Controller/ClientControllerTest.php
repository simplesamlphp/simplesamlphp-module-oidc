<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\SimpleSAML\Modules\OpenIDConnect\Controller;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Modules\OpenIDConnect\Controller\ClientController;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;
use SimpleSAML\Modules\OpenIDConnect\Services\TemplateFactory;
use Zend\Diactoros\ServerRequestFactory;

class ClientControllerTest extends TestCase
{
    /**
     * @var ClientRepository
     */
    private $repository;

    public function setUp()
    {
        $config = [
            'database.dsn' => 'sqlite::memory:',
            'database.username' => null,
            'database.password' => null,
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.slaves' => [],
            'module.enable' => [
                'oidc' => true,
            ],
        ];

        \SimpleSAML_Configuration::loadFromArray($config, '', 'simplesaml');
        (new DatabaseMigration())->migrate();

        $this->repository = new ClientRepository();
    }

    public function testEmptyIndexRoute()
    {
        $templateFactory = $this->prophesize(TemplateFactory::class);
        $templateFactory->render('oidc:clients/index.twig', ['clients' => []])->shouldBeCalled();

        $controller = new ClientController($this->repository, $templateFactory->reveal());
        $controller->index(ServerRequestFactory::fromGlobals());
    }

    public function testNoEmptyIndexRoute()
    {
        $client = self::getClient('client1');
        $this->repository->add($client);

        $templateFactory = $this->prophesize(TemplateFactory::class);
        $templateFactory->render('oidc:clients/index.twig', ['clients' => [$client]])->shouldBeCalled();

        $controller = new ClientController($this->repository, $templateFactory->reveal());
        $controller->index(ServerRequestFactory::fromGlobals());
    }

    public function tearDown()
    {
        $clients = $this->repository->findAll();

        foreach ($clients as $client) {
            $this->repository->delete($client);
        }
    }

    private static function getClient(string $id)
    {
        return ClientEntity::fromData(
            $id,
            'clientsecret',
            'Client',
            'Description',
            'admin',
            ['http://localhost/redirect'],
            ['openid']
        );
    }
}

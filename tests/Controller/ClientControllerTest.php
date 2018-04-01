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

        \SimpleSAML_Configuration::loadFromArray($config, '', 'simplesaml');
        (new DatabaseMigration())->migrate();

        self::$repository = new ClientRepository();
        $_SERVER['REQUEST_URI'] = '/';
    }

    public function tearDown()
    {
        unset($_GET['id']);
        $clients = self::$repository->findAll();

        foreach ($clients as $client) {
            self::$repository->delete($client);
        }
    }

    public function testEmptyIndexRoute()
    {
        $templateFactory = $this->prophesize(TemplateFactory::class);
        $templateFactory->render('oidc:clients/index.twig', ['clients' => []])->shouldBeCalled();

        $controller = new ClientController(self::$repository, $templateFactory->reveal());
        $controller->index(ServerRequestFactory::fromGlobals());
    }

    public function testNoEmptyIndexRoute()
    {
        $client = self::getClient('client1');
        self::$repository->add($client);

        $templateFactory = $this->prophesize(TemplateFactory::class);
        $templateFactory->render('oidc:clients/index.twig', ['clients' => [$client]])->shouldBeCalled();

        $controller = new ClientController(self::$repository, $templateFactory->reveal());
        $controller->index(ServerRequestFactory::fromGlobals());
    }

    public function testValidClientShowRoute()
    {
        $client = self::getClient('client1');
        self::$repository->add($client);

        $_GET['id'] = 'client1';

        $templateFactory = $this->prophesize(TemplateFactory::class);
        $templateFactory->render('oidc:clients/show.twig', ['client' => $client])->shouldBeCalled();

        $controller = new ClientController(self::$repository, $templateFactory->reveal());
        $controller->show(ServerRequestFactory::fromGlobals());
    }

    /**
     * @expectedException \SimpleSAML_Error_BadRequest
     */
    public function testErrorWithoutIdShowRoute()
    {
        $templateFactory = $this->prophesize(TemplateFactory::class);

        $controller = new ClientController(self::$repository, $templateFactory->reveal());
        $controller->show(ServerRequestFactory::fromGlobals());
    }

    /**
     * @expectedException \SimpleSAML_Error_NotFound
     */
    public function testErrorWithoutValidIdShowRoute()
    {
        $_GET['id'] = 'client2';
        $templateFactory = $this->prophesize(TemplateFactory::class);

        $controller = new ClientController(self::$repository, $templateFactory->reveal());
        $controller->show(ServerRequestFactory::fromGlobals());
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

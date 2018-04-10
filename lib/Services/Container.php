<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use League\OAuth2\Server\AuthorizationServer;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use SimpleSAML\Modules\OpenIDConnect\Factories\AuthorizationServerFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\AuthSimpleFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\FormFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\TemplateFactory;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;

class Container implements ContainerInterface
{
    private $services = [];

    public function __construct()
    {
        $clientRepository = new ClientRepository();
        $this->services[ClientRepository::class] = $clientRepository;

        $userRepository = new UserRepository();
        $this->services[UserRepository::class] = $userRepository;

        $configurationService = new ConfigurationService();
        $this->services[ConfigurationService::class] = $configurationService;

        $authSimpleFactory = new AuthSimpleFactory();
        $this->services[AuthSimpleFactory::class] = $authSimpleFactory;

        $formFactory = new FormFactory();
        $this->services[FormFactory::class] = $formFactory;

        $jsonWebKeySetService = new JsonWebKeySetService();
        $this->services[JsonWebKeySetService::class] = $jsonWebKeySetService;

        $sessionMessagesService = new SessionMessagesService();
        $this->services[SessionMessagesService::class] = $sessionMessagesService;

        $templateFactory = new TemplateFactory();
        $this->services[TemplateFactory::class] = $templateFactory;

        $authenticationService = new AuthenticationService(
            $userRepository,
            $authSimpleFactory,
            $configurationService->getOpenIDConnectConfiguration()->getBoolean('useridattr', 'uid')
        );
        $this->services[AuthenticationService::class] = $authenticationService;
    }

    /**
     * @param string $id
     *
     * @throws NotFoundExceptionInterface
     * @throws \SimpleSAML_Error_Exception
     *
     * @return object
     */
    public function get($id)
    {
        if (false === $this->has($id)) {
            throw new class($id) extends \SimpleSAML_Error_Exception implements NotFoundExceptionInterface {
                public function __construct(string $id)
                {
                    parent::__construct("Service not found: {$id}.");
                }
            };
        }

        return $this->services[$id];
    }

    public function has($id)
    {
        return array_key_exists($id, $this->services);
    }
}

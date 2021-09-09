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

namespace spec\SimpleSAML\Module\oidc\Controller;

use Laminas\Diactoros\ServerRequest;
use PhpSpec\ObjectBehavior;
use Psr\Http\Message\UriInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Controller\ClientIndexController;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\XHTML\Template;

class ClientIndexControllerSpec extends ObjectBehavior
{
    /**
     * @return void
     */
    public function let(
        ClientRepository $clientRepository,
        TemplateFactory $templateFactory,
        ServerRequest $request,
        UriInterface $uri,
        AuthContextService $authContextService
    ) {
        $_SERVER['REQUEST_URI'] = '/';
        Configuration::loadFromArray([], '', 'simplesaml');
        $authContextService->isSspAdmin()->willReturn(true);
        $request->getUri()->willReturn($uri);
        $request->getQueryParams()->willReturn(['page' => 1]);
        $uri->getPath()->willReturn('/');

        $this->beConstructedWith($clientRepository, $templateFactory, $authContextService);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(ClientIndexController::class);
    }

    /**
     * @return void
     */
    public function it_shows_client_index(
        ServerRequest $request,
        Template $template,
        TemplateFactory $templateFactory,
        ClientRepository $clientRepository
    ) {
        $clientRepository->findPaginated(1, '', null)->shouldBeCalled()->willReturn([
            'items' => [],
            'numPages' => 1,
            'currentPage' => 1
        ]);
        $templateFactory->render('oidc:clients/index.twig', [
            'clients' => [],
            'numPages' => 1,
            'currentPage' => 1,
            'query' => '',
        ])->shouldBeCalled()->willReturn($template);

        $this->__invoke($request)->shouldBe($template);
    }
}

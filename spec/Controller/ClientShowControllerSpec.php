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
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Controller\ClientShowController;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\XHTML\Template;

class ClientShowControllerSpec extends ObjectBehavior
{
    /**
     * @param \Psr\Http\Message\UriInterface
     *
     * @return void
     */
    public function let(
        ClientRepository $clientRepository,
        AllowedOriginRepository $allowedOriginRepository,
        TemplateFactory $templateFactory,
        ServerRequest $request,
        UriInterface $uri,
        AuthContextService $authContextService
    ) {
        $_SERVER['REQUEST_URI'] = '/';
        Configuration::loadFromArray([], '', 'simplesaml');
        $authContextService->isSspAdmin()->willReturn(true);

        $request->getUri()->willReturn($uri);
        $uri->getPath()->willReturn('/');


        $this->beConstructedWith($clientRepository, $allowedOriginRepository, $templateFactory, $authContextService);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(ClientShowController::class);
    }

    /**
     * @param \SimpleSAML\Module\oidc\Entity\ClientEntity
     *
     * @return void
     */
    public function it_show_client_description(
        ServerRequest $request,
        Template $template,
        TemplateFactory $templateFactory,
        ClientRepository $clientRepository,
        AllowedOriginRepository $allowedOriginRepository,
        ClientEntity $clientEntity
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);

        $clientEntity->getIdentifier()->shouldBeCalled()->willReturn('clientid');
        $clientRepository->findById('clientid', null)->shouldBeCalled()->willReturn($clientEntity);
        $allowedOriginRepository->get('clientid')->shouldBeCalled()->willReturn([]);

        $templateFactory->render('oidc:clients/show.twig', [
            'client' => $clientEntity,
            'allowedOrigins' => []
         ])->shouldBeCalled()
         ->willReturn($template);
        $this->__invoke($request)->shouldBe($template);
    }

    /**
     * @return void
     */
    public function it_throws_id_not_found_exception_in_show_action(
        ServerRequest $request
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn([]);

        $this->shouldThrow(BadRequest::class)->during('__invoke', [$request]);
    }

    /**
     * @return void
     */
    public function it_throws_client_not_found_exception_in_show_action(
        ServerRequest $request,
        ClientRepository $clientRepository
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid', null)->shouldBeCalled()->willReturn(null);

        $this->shouldThrow(NotFound::class)->during('__invoke', [$request]);
    }
}

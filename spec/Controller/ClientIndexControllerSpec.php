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

namespace spec\SimpleSAML\Modules\OpenIDConnect\Controller;

use PhpSpec\ObjectBehavior;
use Psr\Http\Message\UriInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Modules\OpenIDConnect\Controller\ClientIndexController;
use SimpleSAML\Modules\OpenIDConnect\Factories\TemplateFactory;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\XHTML\Template;
use Zend\Diactoros\ServerRequest;

class ClientIndexControllerSpec extends ObjectBehavior
{
    public function let(
        ClientRepository $clientRepository,
        TemplateFactory $templateFactory,
        ServerRequest $request,
        UriInterface $uri
    ) {
        $_SERVER['REQUEST_URI'] = '/';
        Configuration::loadFromArray([], '', 'simplesaml');

        $request->getUri()->willReturn($uri);
        $uri->getPath()->willReturn('/');

        $this->beConstructedWith($clientRepository, $templateFactory);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(ClientIndexController::class);
    }

    public function it_shows_client_index(
        ServerRequest $request,
        Template $template,
        TemplateFactory $templateFactory,
        ClientRepository $clientRepository
    ) {
        $clientRepository->findAll()->shouldBeCalled()->willReturn([]);
        $templateFactory->render('oidc:clients/index.twig', ['clients' => []])->shouldBeCalled()->willReturn($template);

        $this->__invoke($request)->shouldBe($template);
    }
}

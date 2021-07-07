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

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Psr\Http\Message\UriInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Controller\ClientCreateController;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Form\ClientForm;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\XHTML\Template;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;

class ClientCreateControllerSpec extends ObjectBehavior
{
    /**
     * @param \Laminas\Diactoros\ServerRequest $serverRequest
     *
     * @return void
     */
    public function let(
        ConfigurationService $configurationService,
        ClientRepository $clientRepository,
        TemplateFactory $templateFactory,
        FormFactory $formFactory,
        SessionMessagesService $sessionMessagesService,
        ServerRequest $request,
        UriInterface $uri
    ) {
        $_SERVER['REQUEST_URI'] = '/';
        Configuration::loadFromArray([], '', 'simplesaml');

        $configurationService->getOpenIdConnectModuleURL(Argument::any())->willReturn("url");

        $request->getUri()->willReturn($uri);
        $uri->getPath()->willReturn('/');

        $this->beConstructedWith(
            $configurationService,
            $clientRepository,
            $templateFactory,
            $formFactory,
            $sessionMessagesService
        );
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(ClientCreateController::class);
    }

    /**
     * @return void
     */
    public function it_shows_new_client_form(
        ServerRequest $request,
        Template $template,
        TemplateFactory $templateFactory,
        FormFactory $formFactory,
        ClientForm $clientForm
    ) {
        $formFactory->build(ClientForm::class)->shouldBeCalled()->willReturn($clientForm);
        $clientForm->setAction(Argument::any())->shouldBeCalled();
        $clientForm->isSuccess()->shouldBeCalled()->willReturn(false);

        $templateFactory->render('oidc:clients/new.twig', ['form' => $clientForm])
            ->shouldBeCalled()
            ->willReturn($template);
        $this->__invoke($request)->shouldBe($template);
    }

    /**
     * @return void
     */
    public function it_creates_new_client_from_form_data(
        ServerRequest $request,
        FormFactory $formFactory,
        ClientForm $clientForm,
        ClientRepository $clientRepository,
        SessionMessagesService $sessionMessagesService
    ) {
        $formFactory->build(ClientForm::class)->shouldBeCalled()->willReturn($clientForm);
        $clientForm->setAction(Argument::any())->shouldBeCalled();

        $clientForm->isSuccess()->shouldBeCalled()->willReturn(true);
        $clientForm->getValues()->shouldBeCalled()->willReturn([
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => ['http://localhost/redirect'],
            'scopes' => ['openid'],
            'is_enabled' => true,
            'is_confidential' => false,
        ]);

        $clientRepository->add(Argument::type(ClientEntity::class))->shouldBeCalled();
        $sessionMessagesService->addMessage('{oidc:client:added}')->shouldBeCalled();

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }
}

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

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Psr\Http\Message\UriInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Controller\ClientCreateController;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Form\ClientForm;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\XHTML\Template;

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
        AllowedOriginRepository $allowedOriginRepository,
        TemplateFactory $templateFactory,
        FormFactory $formFactory,
        SessionMessagesService $sessionMessagesService,
        ServerRequest $request,
        UriInterface $uri,
        AuthContextService $authContextService
    ) {
        $_SERVER['REQUEST_URI'] = '/';
        Configuration::loadFromArray([], '', 'simplesaml');

        $configurationService->getOpenIdConnectModuleURL(Argument::any())->willReturn("url");
        $authContextService->isSspAdmin()->willReturn(true);
        $request->getUri()->willReturn($uri);
        $uri->getPath()->willReturn('/');

        $this->beConstructedWith(
            $clientRepository,
            $allowedOriginRepository,
            $templateFactory,
            $formFactory,
            $sessionMessagesService,
            $authContextService
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

        $templateFactory->render('oidc:clients/new.twig', [
            'form' => $clientForm,
            'regexUri' => ClientForm::REGEX_URI,
            'regexAllowedOriginUrl' => ClientForm::REGEX_ALLOWED_ORIGIN_URL,
            'regexHttpUri' => ClientForm::REGEX_HTTP_URI,
        ])
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
        AllowedOriginRepository $allowedOriginRepository,
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
            'allowed_origin' => [],
            'post_logout_redirect_uri' => [],
            'backchannel_logout_uri' => null,
        ]);

        $clientRepository->add(Argument::type(ClientEntity::class))->shouldBeCalled();

        $allowedOriginRepository->set(Argument::type('string'), [])->shouldBeCalled();

        $sessionMessagesService->addMessage('{oidc:client:added}')->shouldBeCalled();

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }

    /**
     * @return void
     */
    public function it_owner_set_in_new_client(
        ServerRequest $request,
        FormFactory $formFactory,
        ClientForm $clientForm,
        ClientRepository $clientRepository,
        SessionMessagesService $sessionMessagesService,
        AuthContextService $authContextService
    ) {
        $authContextService->isSspAdmin()->shouldBeCalled()->willReturn(false);
        $authContextService->getAuthUserId()->willReturn('ownerUsername');
        $formFactory->build(ClientForm::class)->shouldBeCalled()->willReturn($clientForm);
        $clientForm->setAction(Argument::any())->shouldBeCalled();

        $clientForm->isSuccess()->shouldBeCalled()->willReturn(true);
        $clientForm->getValues()->shouldBeCalled()->willReturn(
            [
                'name' => 'name',
                'description' => 'description',
                'auth_source' => 'auth_source',
                'redirect_uri' => ['http://localhost/redirect'],
                'scopes' => ['openid'],
                'is_enabled' => true,
                'is_confidential' => false,
                'owner' => 'wrongOwner',
                'allowed_origin' => [],
                'post_logout_redirect_uri' => [],
                'backchannel_logout_uri' => null,
            ]
        );

        $clientRepository->add(Argument::which('getOwner', 'ownerUsername'))->shouldBeCalled();
        $sessionMessagesService->addMessage('{oidc:client:added}')->shouldBeCalled();

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }
}

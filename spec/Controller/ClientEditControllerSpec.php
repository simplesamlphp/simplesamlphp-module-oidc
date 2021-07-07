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
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Controller\ClientEditController;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Form\ClientForm;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\XHTML\Template;

class ClientEditControllerSpec extends ObjectBehavior
{
    /**
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

        $configurationService->getOpenIdConnectModuleURL()->willReturn("url");

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
        $this->shouldHaveType(ClientEditController::class);
    }

    /**
     * @return void
     */
    public function it_shows_edit_client_form(
        ServerRequest $request,
        Template $template,
        TemplateFactory $templateFactory,
        FormFactory $formFactory,
        ClientForm $clientForm,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity
    ) {
        $data = [
            'id' => 'clientid',
            'secret' => 'validsecret',
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => ['http://localhost/redirect'],
            'scopes' => ['openid'],
            'is_enabled' => true,
        ];
        $clientEntity->getIdentifier()->shouldBeCalled()->willReturn('clientid');

        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->toArray()->shouldBeCalled()->willReturn($data);

        $formFactory->build(ClientForm::class)->shouldBeCalled()->willReturn($clientForm);
        $clientForm->setAction(Argument::any())->shouldBeCalled();
        $clientForm->setDefaults($data)->shouldBeCalled();

        $clientForm->isSuccess()->shouldBeCalled()->willReturn(false);

        $templateFactory->render('oidc:clients/edit.twig', ['form' => $clientForm])
            ->shouldBeCalled()->willReturn($template);
        $this->__invoke($request)->shouldBe($template);
    }

    /**
     * @return void
     */
    public function it_updates_client_from_edit_client_form_data(
        ServerRequest $request,
        FormFactory $formFactory,
        ClientForm $clientForm,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity,
        SessionMessagesService $sessionMessagesService
    ) {
        $data = [
            'id' => 'clientid',
            'secret' => 'validsecret',
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => ['http://localhost/redirect'],
            'scopes' => ['openid'],
            'is_enabled' => true,
            'is_confidential' => false,
        ];

        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->getIdentifier()->shouldBeCalled()->willReturn('clientid');
        $clientEntity->getSecret()->shouldBeCalled()->willReturn('validsecret');
        $clientEntity->toArray()->shouldBeCalled()->willReturn($data);

        $formFactory->build(ClientForm::class)->shouldBeCalled()->willReturn($clientForm);
        $clientForm->setAction(Argument::any())->shouldBeCalled();
        $clientForm->isSuccess()->shouldBeCalled()->willReturn(true);
        $clientForm->setDefaults($data)->shouldBeCalled();
        $clientForm->getValues()->shouldBeCalled()->willReturn([
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => ['http://localhost/redirect'],
            'scopes' => ['openid'],
            'is_enabled' => true,
            'is_confidential' => false,
        ]);

        $clientRepository->update(Argument::exact(ClientEntity::fromData(
            'clientid',
            'validsecret',
            'name',
            'description',
            ['http://localhost/redirect'],
            ['openid'],
            true,
            false,
            'auth_source'
        )))->shouldBeCalled();
        $sessionMessagesService->addMessage('{oidc:client:updated}')->shouldBeCalled();

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }

    /**
     * @return void
     */
    public function it_throws_id_not_found_exception_in_edit_action(
        ServerRequest $request
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn([]);

        $this->shouldThrow(BadRequest::class)->during('__invoke', [$request]);
    }

    /**
     * @return void
     */
    public function it_throws_client_not_found_exception_in_edit_action(
        ServerRequest $request,
        ClientRepository $clientRepository
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn(null);

        $this->shouldThrow(NotFound::class)->during('__invoke', [$request]);
    }
}

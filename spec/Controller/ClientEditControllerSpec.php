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
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
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
        $authContextService->isSspAdmin()->willReturn(true);
        $configurationService->getOpenIdConnectModuleURL()->willReturn("url");

        $request->withQueryParams(Argument::any())->willReturn($request);
        $request->getUri()->willReturn($uri);
        $request->getRequestTarget()->willReturn('/');
        $uri->getPath()->willReturn('/');

        $this->beConstructedWith(
            $configurationService,
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
        AllowedOriginRepository $allowedOriginRepository,
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
            'allowed_origin' => [],
        ];
        $clientEntity->getIdentifier()->shouldBeCalled()->willReturn('clientid');

        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid', null)->shouldBeCalled()->willReturn($clientEntity);
        $allowedOriginRepository->get('clientid')->shouldBeCalled()->willReturn([]);
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
        AllowedOriginRepository $allowedOriginRepository,
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
            'owner' => 'existingOwner',
            'allowed_origin' => [],
        ];

        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid', null)->shouldBeCalled()->willReturn($clientEntity);
        $allowedOriginRepository->get('clientid')->shouldBeCalled()->willReturn([]);
        $clientEntity->getIdentifier()->shouldBeCalled()->willReturn('clientid');
        $clientEntity->getSecret()->shouldBeCalled()->willReturn('validsecret');
        $clientEntity->getOwner()->shouldBeCalled()->willReturn('existingOwner');
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
            'owner' => 'existingOwner',
            'allowed_origin' => [],
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
            'auth_source',
            'existingOwner'
        )), null)->shouldBeCalled();

        $allowedOriginRepository->set('clientid', [])->shouldBeCalled();
        $sessionMessagesService->addMessage('{oidc:client:updated}')->shouldBeCalled();

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }

    /**
     * @return void
     */
    public function it_sends_owner_arg_to_repo_on_update(
        ServerRequest $request,
        FormFactory $formFactory,
        ClientForm $clientForm,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity,
        SessionMessagesService $sessionMessagesService,
        AuthContextService $authContextService,
        AllowedOriginRepository $allowedOriginRepository
    ) {
        $authContextService->isSspAdmin()->shouldBeCalled()->willReturn(false);
        $authContextService->getAuthUserId()->willReturn('authedUserId');
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
            'owner' => 'existingOwner',
            'allowed_origin' => [],
        ];

        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid', 'authedUserId')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->getIdentifier()->shouldBeCalled()->willReturn('clientid');
        $clientEntity->getSecret()->shouldBeCalled()->willReturn('validsecret');
        $clientEntity->getOwner()->shouldBeCalled()->willReturn('existingOwner');
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
                                                                   'owner' => 'existingOwner',
                                                                   'allowed_origin' => [],
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
            'auth_source',
            'existingOwner'
        )), 'authedUserId')->shouldBeCalled();

        $allowedOriginRepository->get('clientid')->shouldBeCalled()->willReturn([]);
        $allowedOriginRepository->set('clientid', [])->shouldBeCalled();

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
        $clientRepository->findById('clientid', null)->shouldBeCalled()->willReturn(null);

        $this->shouldThrow(NotFound::class)->during('__invoke', [$request]);
    }
}

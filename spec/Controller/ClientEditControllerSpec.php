<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\SimpleSAML\Modules\OpenIDConnect\Controller;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Psr\Http\Message\UriInterface;
use SimpleSAML\Modules\OpenIDConnect\Controller\ClientEditController;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Factories\FormFactory;
use SimpleSAML\Modules\OpenIDConnect\Factories\TemplateFactory;
use SimpleSAML\Modules\OpenIDConnect\Form\ClientForm;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;
use Zend\Diactoros\Response\RedirectResponse;
use Zend\Diactoros\ServerRequest;

class ClientEditControllerSpec extends ObjectBehavior
{
    public function let(
        ClientRepository $clientRepository,
        TemplateFactory $templateFactory,
        FormFactory $formFactory,
        SessionMessagesService $sessionMessagesService,
        ServerRequest $request,
        UriInterface $uri
    ) {
        $_SERVER['REQUEST_URI'] = '/';
        \SimpleSAML_Configuration::loadFromArray([], '', 'simplesaml');

        $request->getUri()->willReturn($uri);
        $uri->getPath()->willReturn('/');

        $this->beConstructedWith($clientRepository, $templateFactory, $formFactory, $sessionMessagesService);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(ClientEditController::class);
    }

    public function it_shows_edit_client_form(
        ServerRequest $request,
        \SimpleSAML_XHTML_Template $template,
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

        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->toArray()->shouldBeCalled()->willReturn($data);

        $formFactory->build(ClientForm::class)->shouldBeCalled()->willReturn($clientForm);
        $clientForm->setAction(Argument::any())->shouldBeCalled();
        $clientForm->setDefaults($data)->shouldBeCalled();

        $clientForm->isSuccess()->shouldBeCalled()->willReturn(false);

        $templateFactory->render('oidc:clients/edit.twig', ['form' => $clientForm])->shouldBeCalled()->willReturn($template);
        $this->__invoke($request)->shouldBe($template);
    }

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
        ]);

        $clientRepository->update(Argument::exact(ClientEntity::fromData(
            'clientid',
            'validsecret',
            'name',
            'description',
            'auth_source',
            ['http://localhost/redirect'],
            ['openid'],
            true
        )))->shouldBeCalled();
        $sessionMessagesService->addMessage('{oidc:client:updated}')->shouldBeCalled();

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }

    public function it_throws_id_not_found_exception_in_edit_action(
        ServerRequest $request
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn([]);

        $this->shouldThrow(\SimpleSAML_Error_BadRequest::class)->during('__invoke', [$request]);
    }

    public function it_throws_client_not_found_exception_in_edit_action(
        ServerRequest $request,
        ClientRepository $clientRepository
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn(null);

        $this->shouldThrow(\SimpleSAML_Error_NotFound::class)->during('__invoke', [$request]);
    }
}

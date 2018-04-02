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
use SimpleSAML\Modules\OpenIDConnect\Controller\ClientController;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Form\ClientForm;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\FormFactory;
use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;
use SimpleSAML\Modules\OpenIDConnect\Services\TemplateFactory;
use SimpleSAML\Modules\OpenIDConnect\Templates\RedirectResponse;
use Zend\Diactoros\ServerRequest;

class ClientControllerSpec extends ObjectBehavior
{
    public function let(
        ClientRepository $clientRepository,
        TemplateFactory $templateFactory,
        SessionMessagesService $sessionMessagesService,
        FormFactory $formFactory,
        ServerRequest $request,
        UriInterface $uri
    ) {
        $_SERVER['REQUEST_URI'] = '/';
        \SimpleSAML_Configuration::loadFromArray([], '', 'simplesaml');

        $request->getUri()->willReturn($uri);
        $uri->getPath()->willReturn('/');
        $this->beConstructedWith($clientRepository, $templateFactory, $sessionMessagesService, $formFactory);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(ClientController::class);
    }

    public function it_shows_client_index(
        ServerRequest $request,
        \SimpleSAML_XHTML_Template $template,
        TemplateFactory $templateFactory,
        ClientRepository $clientRepository
    ) {
        $clientRepository->findAll()->shouldBeCalled()->willReturn([]);
        $templateFactory->render('oidc:clients/index.twig', ['clients' => []])->shouldBeCalled()->willReturn($template);

        $this->index($request)->shouldBe($template);
    }

    public function it_show_client_description(
        ServerRequest $request,
        \SimpleSAML_XHTML_Template $template,
        TemplateFactory $templateFactory,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);

        $templateFactory->render('oidc:clients/show.twig', ['client' => $clientEntity])->shouldBeCalled()->willReturn($template);
        $this->show($request)->shouldBe($template);
    }

    public function it_throws_id_not_found_exception_in_show_action(
        ServerRequest $request
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn([]);

        $this->shouldThrow(\SimpleSAML_Error_BadRequest::class)->during('show', [$request]);
    }

    public function it_throws_client_not_found_exception_in_show_action(
        ServerRequest $request,
        ClientRepository $clientRepository
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn(null);

        $this->shouldThrow(\SimpleSAML_Error_NotFound::class)->during('show', [$request]);
    }

    public function it_asks_confirmation_before_delete_client(
        ServerRequest $request,
        \SimpleSAML_XHTML_Template $template,
        TemplateFactory $templateFactory,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['id' => 'clientid']);
        $request->getParsedBody()->shouldBeCalled()->willReturn([]);
        $request->getMethod()->shouldBeCalled()->willReturn('get');
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);

        $templateFactory->render('oidc:clients/delete.twig', ['client' => $clientEntity])->shouldBeCalled()->willReturn($template);
        $this->delete($request)->shouldBe($template);
    }

    public function it_throws_id_not_found_exception_in_delete_action(
        ServerRequest $request
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn([]);

        $this->shouldThrow(\SimpleSAML_Error_BadRequest::class)->during('delete', [$request]);
    }

    public function it_throws_client_not_found_exception_in_delete_action(
        ServerRequest $request,
        ClientRepository $clientRepository
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn(null);

        $this->shouldThrow(\SimpleSAML_Error_NotFound::class)->during('delete', [$request]);
    }

    public function it_throws_secret_not_found_exception_in_delete_action(
        ServerRequest $request,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $request->getParsedBody()->shouldBeCalled()->willReturn([]);
        $request->getMethod()->shouldBeCalled()->willReturn('post');

        $this->shouldThrow(\SimpleSAML_Error_BadRequest::class)->during('delete', [$request]);
    }

    public function it_throws_secret_invalid_exception_in_delete_action(
        ServerRequest $request,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['id' => 'clientid']);
        $request->getParsedBody()->shouldBeCalled()->willReturn(['secret' => 'invalidsecret']);
        $request->getMethod()->shouldBeCalled()->willReturn('post');

        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->getSecret()->shouldBeCalled()->willReturn('validsecret');

        $this->shouldThrow(\SimpleSAML_Error_BadRequest::class)->during('delete', [$request]);
    }

    public function it_deletes_client(
        ServerRequest $request,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity,
        SessionMessagesService $sessionMessagesService
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['id' => 'clientid']);
        $request->getParsedBody()->shouldBeCalled()->willReturn(['secret' => 'validsecret']);
        $request->getMethod()->shouldBeCalled()->willReturn('post');

        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->getSecret()->shouldBeCalled()->willReturn('validsecret');
        $clientRepository->delete($clientEntity)->shouldBeCalled();

        $sessionMessagesService->addMessage('{oidc:client:removed}')->shouldBeCalled();

        $this->delete($request)->shouldBeLike(new RedirectResponse('index.php'));
    }

    public function it_shows_new_client_form(
        ServerRequest $request,
        \SimpleSAML_XHTML_Template $template,
        TemplateFactory $templateFactory,
        FormFactory $formFactory,
        ClientForm $clientForm
    ) {
        $formFactory->build(ClientForm::class)->shouldBeCalled()->willReturn($clientForm);
        $clientForm->setAction(Argument::any())->shouldBeCalled();
        $clientForm->isSuccess()->shouldBeCalled()->willReturn(false);

        $templateFactory->render('oidc:clients/new.twig', ['form' => $clientForm])->shouldBeCalled()->willReturn($template);
        $this->new($request)->shouldBe($template);
    }

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
        ]);

        $clientRepository->add(Argument::type(ClientEntity::class))->shouldBeCalled();
        $sessionMessagesService->addMessage('{oidc:client:added}')->shouldBeCalled();

        $this->new($request)->shouldBeLike(new RedirectResponse('index.php'));
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
        ];

        $request->getQueryParams()->shouldBeCalled()->willReturn(['id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->toArray()->shouldBeCalled()->willReturn($data);

        $formFactory->build(ClientForm::class)->shouldBeCalled()->willReturn($clientForm);
        $clientForm->setAction(Argument::any())->shouldBeCalled();
        $clientForm->setDefaults($data)->shouldBeCalled();

        $clientForm->isSuccess()->shouldBeCalled()->willReturn(false);

        $templateFactory->render('oidc:clients/edit.twig', ['form' => $clientForm])->shouldBeCalled()->willReturn($template);
        $this->edit($request)->shouldBe($template);
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
        ];

        $request->getQueryParams()->shouldBeCalled()->willReturn(['id' => 'clientid']);
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
        ]);

        $clientRepository->update(Argument::exact(ClientEntity::fromData(
            'clientid',
            'validsecret',
            'name',
            'description',
            'auth_source',
            ['http://localhost/redirect'],
            ['openid']
        )))->shouldBeCalled();
        $sessionMessagesService->addMessage('{oidc:client:updated}')->shouldBeCalled();

        $this->edit($request)->shouldBeLike(new RedirectResponse('index.php'));
    }

    public function it_throws_id_not_found_exception_in_edit_action(
        ServerRequest $request
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn([]);

        $this->shouldThrow(\SimpleSAML_Error_BadRequest::class)->during('edit', [$request]);
    }

    public function it_throws_client_not_found_exception_in_edit_action(
        ServerRequest $request,
        ClientRepository $clientRepository
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn(null);

        $this->shouldThrow(\SimpleSAML_Error_NotFound::class)->during('edit', [$request]);
    }
}

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
use Psr\Http\Message\UriInterface;
use SimpleSAML\Modules\OpenIDConnect\Controller\ClientDeleteController;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Factories\TemplateFactory;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\SessionMessagesService;
use Zend\Diactoros\Response\RedirectResponse;
use Zend\Diactoros\ServerRequest;

class ClientDeleteControllerSpec extends ObjectBehavior
{
    public function let(
        ClientRepository $clientRepository,
        TemplateFactory $templateFactory,
        SessionMessagesService $sessionMessagesService,
        ServerRequest $request,
        UriInterface $uri
    ) {
        $_SERVER['REQUEST_URI'] = '/';
        \SimpleSAML_Configuration::loadFromArray([], '', 'simplesaml');

        $request->getUri()->willReturn($uri);
        $uri->getPath()->willReturn('/');

        $this->beConstructedWith($clientRepository, $templateFactory, $sessionMessagesService);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(ClientDeleteController::class);
    }

    public function it_asks_confirmation_before_delete_client(
        ServerRequest $request,
        \SimpleSAML_XHTML_Template $template,
        TemplateFactory $templateFactory,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $request->getParsedBody()->shouldBeCalled()->willReturn([]);
        $request->getMethod()->shouldBeCalled()->willReturn('get');
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);

        $templateFactory->render('oidc:clients/delete.twig', ['client' => $clientEntity])->shouldBeCalled()->willReturn($template);
        $this->__invoke($request)->shouldBe($template);
    }

    public function it_throws_id_not_found_exception_in_delete_action(
        ServerRequest $request
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn([]);

        $this->shouldThrow(\SimpleSAML_Error_BadRequest::class)->during('__invoke', [$request]);
    }

    public function it_throws_client_not_found_exception_in_delete_action(
        ServerRequest $request,
        ClientRepository $clientRepository
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn(null);

        $this->shouldThrow(\SimpleSAML_Error_NotFound::class)->during('__invoke', [$request]);
    }

    public function it_throws_secret_not_found_exception_in_delete_action(
        ServerRequest $request,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $request->getParsedBody()->shouldBeCalled()->willReturn([]);
        $request->getMethod()->shouldBeCalled()->willReturn('post');

        $this->shouldThrow(\SimpleSAML_Error_BadRequest::class)->during('__invoke', [$request]);
    }

    public function it_throws_secret_invalid_exception_in_delete_action(
        ServerRequest $request,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $request->getParsedBody()->shouldBeCalled()->willReturn(['secret' => 'invalidsecret']);
        $request->getMethod()->shouldBeCalled()->willReturn('post');

        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->getSecret()->shouldBeCalled()->willReturn('validsecret');

        $this->shouldThrow(\SimpleSAML_Error_BadRequest::class)->during('__invoke', [$request]);
    }

    public function it_deletes_client(
        ServerRequest $request,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity,
        SessionMessagesService $sessionMessagesService
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $request->getParsedBody()->shouldBeCalled()->willReturn(['secret' => 'validsecret']);
        $request->getMethod()->shouldBeCalled()->willReturn('post');

        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->getSecret()->shouldBeCalled()->willReturn('validsecret');
        $clientRepository->delete($clientEntity)->shouldBeCalled();

        $sessionMessagesService->addMessage('{oidc:client:removed}')->shouldBeCalled();

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }
}

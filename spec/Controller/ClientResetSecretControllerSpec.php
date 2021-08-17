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
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Controller\ClientResetSecretController;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;

class ClientResetSecretControllerSpec extends ObjectBehavior
{
    /**
     * @return void
     */
    public function let(
        ClientRepository $clientRepository,
        SessionMessagesService $sessionMessagesService,
        ServerRequest $request,
        UriInterface $uri
    ) {
        $_SERVER['REQUEST_URI'] = '/';
        Configuration::loadFromArray([], '', 'simplesaml');

        $request->getUri()->willReturn($uri);
        $uri->getPath()->willReturn('/');

        $this->beConstructedWith($clientRepository, $sessionMessagesService);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(ClientResetSecretController::class);
    }

    /**
     * @return void
     */
    public function it_throws_id_not_found_exception_in_reset_secret_action(
        ServerRequest $request
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn([]);

        $this->shouldThrow(BadRequest::class)->during('__invoke', [$request]);
    }

    /**
     * @return void
     */
    public function it_throws_client_not_found_exception_in_reset_secret_action(
        ServerRequest $request,
        ClientRepository $clientRepository
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn(null);

        $this->shouldThrow(NotFound::class)->during('__invoke', [$request]);
    }

    /**
     * @param \SimpleSAML\Module\oidc\Entity\ClientEntity
     *
     * @return void
     */
    public function it_throws_secret_not_found_exception_in_reset_secret_action(
        ServerRequest $request,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $request->getParsedBody()->shouldBeCalled()->willReturn([]);
        $request->getMethod()->shouldBeCalled()->willReturn('post');

        $this->shouldThrow(BadRequest::class)->during('__invoke', [$request]);
    }

    /**
     * @param \SimpleSAML\Module\oidc\Entity\ClientEntity
     *
     * @return void
     */
    public function it_throws_secret_invalid_exception_in_reset_secret_action(
        ServerRequest $request,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $request->getParsedBody()->shouldBeCalled()->willReturn(['secret' => 'invalidsecret']);
        $request->getMethod()->shouldBeCalled()->willReturn('post');

        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->getSecret()->shouldBeCalled()->willReturn('validsecret');

        $this->shouldThrow(BadRequest::class)->during('__invoke', [$request]);
    }

    /**
     * @param \SimpleSAML\Module\oidc\Entity\ClientEntity
     *
     * @return void
     */
    public function it_reset_secrets_client(
        ServerRequest $request,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity,
        SessionMessagesService $sessionMessagesService
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $request->getParsedBody()->shouldBeCalled()->willReturn(['secret' => 'validsecret']);
        $request->getMethod()->shouldBeCalled()->willReturn('post');

        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->getIdentifier()->shouldBeCalled()->willReturn('clientid');
        $clientEntity->getSecret()->shouldBeCalled()->willReturn('validsecret');
        $clientEntity->restoreSecret(Argument::any())->shouldBeCalled();
        $clientRepository->update($clientEntity)->shouldBeCalled();

        $sessionMessagesService->addMessage('{oidc:client:secret_updated}')->shouldBeCalled();

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }

    /**
     * @param \SimpleSAML\Module\oidc\Entity\ClientEntity
     *
     * @return void
     */
    public function it_send_back_to_show_client_if_not_post_method_in_reset_action(
        ServerRequest $request,
        ClientRepository $clientRepository,
        ClientEntity $clientEntity,
        SessionMessagesService $sessionMessagesService
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $request->getParsedBody()->shouldBeCalled()->willReturn(['secret' => 'validsecret']);
        $request->getMethod()->shouldBeCalled()->willReturn('get');

        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->getIdentifier()->shouldBeCalled()->willReturn('clientid');

        $this->__invoke($request)->shouldBeAnInstanceOf(RedirectResponse::class);
    }
}

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

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Modules\OpenIDConnect\Controller\OAuth2AuthorizationController;
use SimpleSAML\Modules\OpenIDConnect\Entity\ClientEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\AuthenticationService;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class OAuth2AuthorizationControllerSpec extends ObjectBehavior
{
    /**
     * @return void
     */
    public function let(
        ClientRepository $clientRepository,
        AuthenticationService $authenticationService,
        AuthorizationServer $authorizationServer
    ) {
        $this->beConstructedWith($clientRepository, $authenticationService, $authorizationServer);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(OAuth2AuthorizationController::class);
    }

    /**
     * @param \Zend\Diactoros\Response $response
     *
     * @return void
     */
    public function it_completes_authorization_request(
        ClientRepository $clientRepository,
        ClientEntity $clientEntity,
        UserEntity $userEntity,
        AuthenticationService $authenticationService,
        AuthorizationServer $authorizationServer,
        AuthorizationRequest $authorizationRequest,
        ServerRequest $request,
        ResponseInterface $response
    ) {
        $request->getQueryParams()->shouldBeCalled()->willReturn(['client_id' => 'clientid']);
        $clientRepository->findById('clientid')->shouldBeCalled()->willReturn($clientEntity);
        $clientEntity->getAuthSource()->shouldBeCalled()->willReturn('authSource');

        $authenticationService->getAuthenticateUser('authSource')->shouldBeCalled()->willReturn($userEntity);
        $authorizationServer->validateAuthorizationRequest($request)->shouldBeCalled()->willReturn($authorizationRequest);
        $authorizationRequest->setUser($userEntity)->shouldBeCalled();
        $authorizationRequest->setAuthorizationApproved(true)->shouldBeCalled();

        $authorizationServer->completeAuthorizationRequest($authorizationRequest, Argument::type(Response::class))->shouldBeCalled()->willReturn($response);

        $this->__invoke($request)->shouldBe($response);
    }
}

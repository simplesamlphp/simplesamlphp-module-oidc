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

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Module\oidc\Controller\OAuth2AuthorizationController;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

class OAuth2AuthorizationControllerSpec extends ObjectBehavior
{
    /**
     * @param AuthenticationService $authenticationService
     * @param AuthorizationServer $authorizationServer
     * @param ConfigurationService $configurationService
     * @return void
     */
    public function let(
        AuthenticationService $authenticationService,
        AuthorizationServer $authorizationServer,
        ConfigurationService $configurationService
    ): void {
        $this->beConstructedWith($authenticationService, $authorizationServer, $configurationService);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(OAuth2AuthorizationController::class);
    }

    /**
     * @param UserEntity $userEntity
     * @param AuthenticationService $authenticationService
     * @param AuthorizationServer $authorizationServer
     * @param OAuth2AuthorizationRequest $authorizationRequest
     * @param ServerRequest $request
     * @param ResponseInterface $response
     * @return void
     * @throws OAuthServerException
     */
    public function it_completes_authorization_request(
        UserEntity $userEntity,
        AuthenticationService $authenticationService,
        AuthorizationServer $authorizationServer,
        OAuth2AuthorizationRequest $authorizationRequest,
        ServerRequest $request,
        ResponseInterface $response
    ) {
        $authorizationServer->validateAuthorizationRequest($request)
            ->shouldBeCalled()
            ->willReturn($authorizationRequest);
        $authenticationService->getAuthenticateUser($request)
            ->shouldBeCalled()
            ->willReturn($userEntity);
        $authorizationRequest->setUser($userEntity)
            ->shouldBeCalled();
        $authorizationRequest->setAuthorizationApproved(true)
            ->shouldBeCalled();

        $authorizationServer->completeAuthorizationRequest($authorizationRequest, Argument::type(Response::class))
            ->shouldBeCalled()
            ->willReturn($response);

        $this->__invoke($request)
            ->shouldBe($response);
    }

    /**
     * @param UserEntity $userEntity
     * @param AuthenticationService $authenticationService
     * @param AuthorizationServer $authorizationServer
     * @param OAuth2AuthorizationRequest $authorizationRequest
     * @param ServerRequest $request
     * @param ResponseInterface $response
     * @param ConfigurationService $configurationService
     * @return void
     * @throws OAuthServerException
     */
    public function it_populates_authn_related_props_in_authorization_request(
        UserEntity $userEntity,
        AuthenticationService $authenticationService,
        AuthorizationServer $authorizationServer,
        AuthorizationRequest $authorizationRequest,
        ServerRequest $request,
        ResponseInterface $response,
        ConfigurationService $configurationService
    ) {
        $authSourceId = 'some-auth-source';
        $acrValues = ['values' => ['1', '0']];
        $sessionId = 'session123';

        $authorizationServer->validateAuthorizationRequest($request)
            ->shouldBeCalled()
            ->willReturn($authorizationRequest);
        $authenticationService->isCookieBasedAuthn()->willReturn(false);
        $authenticationService->getAuthSourceId()->willReturn($authSourceId);
        $authenticationService->getSessionId()->willReturn($sessionId);
        $authenticationService->getAuthenticateUser($request)
            ->shouldBeCalled()
            ->willReturn($userEntity);

        $authorizationRequest->setIsCookieBasedAuthn(false);
        $authorizationRequest->setAuthSourceId($authSourceId);
        $authorizationRequest->setSessionId($sessionId);
        $authorizationRequest->setUser($userEntity)
            ->shouldBeCalled();
        $authorizationRequest->setAuthorizationApproved(true)
            ->shouldBeCalled();

        $authorizationRequest->getRequestedAcrValues()->shouldBeCalled()->willReturn($acrValues);
        $authorizationRequest->getAuthSourceId()->shouldBeCalled()->willReturn($authSourceId);
        $authorizationRequest->getIsCookieBasedAuthn()->shouldBeCalled()->willReturn(false);

        $configurationService->getAuthSourcesToAcrValuesMap()->willReturn([$authSourceId => ['1', '0']]);
        $configurationService->getForcedAcrValueForCookieAuthentication()->willReturn(null);

        $authorizationRequest->setAcr('1')->shouldBeCalled();

        $authorizationServer->completeAuthorizationRequest($authorizationRequest, Argument::type(Response::class))
            ->shouldBeCalled()
            ->willReturn($response);

        $this->__invoke($request)
            ->shouldBe($response);
    }
}

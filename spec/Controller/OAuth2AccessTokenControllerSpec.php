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

use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Module\oidc\Controller\OAuth2AccessTokenController;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;

class OAuth2AccessTokenControllerSpec extends ObjectBehavior
{
    /**
     * @return void
     */
    public function let(AuthorizationServer $authorizationServer)
    {
        $this->beConstructedWith($authorizationServer);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(OAuth2AccessTokenController::class);
    }

    /**
     * @param \Laminas\Diactoros\Response $response
     *
     * @return void
     */
    public function it_responds_to_access_token_request(
        AuthorizationServer $authorizationServer,
        ServerRequest $request,
        ResponseInterface $response
    ) {
        $authorizationServer->respondToAccessTokenRequest($request, Argument::type(Response::class))
            ->shouldBeCalled()
            ->willReturn($response);

        $this->__invoke($request)->shouldBe($response);
    }
}

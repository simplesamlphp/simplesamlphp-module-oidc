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

use League\OAuth2\Server\AuthorizationServer;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Modules\OpenIDConnect\Controller\OAuth2AccessTokenController;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class OAuth2AccessTokenControllerSpec extends ObjectBehavior
{
    public function let(AuthorizationServer $authorizationServer)
    {
        $this->beConstructedWith($authorizationServer);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(OAuth2AccessTokenController::class);
    }

    public function it_responds_to_access_token_request(
        AuthorizationServer $authorizationServer,
        ServerRequest $request,
        ResponseInterface $response
    ) {
        $authorizationServer->respondToAccessTokenRequest($request, Argument::type(Response::class))->shouldBeCalled()->willReturn($response);

        $this->__invoke($request)->shouldBe($response);
    }
}

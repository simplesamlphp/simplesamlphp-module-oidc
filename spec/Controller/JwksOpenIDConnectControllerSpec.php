<?php

namespace spec\SimpleSAML\Modules\OpenIDConnect\Controller;

use SimpleSAML\Modules\OpenIDConnect\Controller\JwksOpenIDConnectController;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use SimpleSAML\Modules\OpenIDConnect\Services\JsonWebKeySetService;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\ServerRequest;

class JwksOpenIDConnectControllerSpec extends ObjectBehavior
{
    function let(JsonWebKeySetService $jsonWebKeySet)
    {
        $this->beConstructedWith($jsonWebKeySet);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(JwksOpenIDConnectController::class);
    }

    function it_return_json_keys(
        ServerRequest $request,
        JsonWebKeySetService $jsonWebKeySet
    )
    {
        $jsonWebKeySet->keys()->shouldBeCalled()->willReturn([
            [
                'kty' => 'RSA',
                'n' => 'n',
                'e' => 'e',
                'use' => 'sig',
                'alg' => 'RS256',
            ]
        ]);

        $this->index($request)->shouldBeAnInstanceOf(JsonResponse::class);
    }
}

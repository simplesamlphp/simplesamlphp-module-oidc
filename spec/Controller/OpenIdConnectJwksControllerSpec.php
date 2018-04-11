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
use SimpleSAML\Modules\OpenIDConnect\Controller\OpenIdConnectJwksController;
use SimpleSAML\Modules\OpenIDConnect\Services\JsonWebKeySetService;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\ServerRequest;

class OpenIdConnectJwksControllerSpec extends ObjectBehavior
{
    public function let(JsonWebKeySetService $jsonWebKeySet)
    {
        $this->beConstructedWith($jsonWebKeySet);
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType(OpenIdConnectJwksController::class);
    }

    public function it_returns_json_keys(
        ServerRequest $request,
        JsonWebKeySetService $jsonWebKeySet
    ) {
        $keys = [
            0 => [
                'kty' => 'RSA',
                'n' => 'n',
                'e' => 'e',
                'use' => 'sig',
                'alg' => 'RS256',
            ],
        ];

        $jsonWebKeySet->keys()->shouldBeCalled()->willReturn($keys);

        $this->jwks($request)->shouldHavePayload(['keys' => $keys]);
    }

    public function getMatchers(): array
    {
        return [
            'havePayload' => function (JsonResponse $subject, $payload) {
                return $payload === $subject->getPayload();
            },
        ];
    }
}

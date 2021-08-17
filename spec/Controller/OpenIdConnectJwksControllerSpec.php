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
use SimpleSAML\Module\oidc\Controller\OpenIdConnectJwksController;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequest;

class OpenIdConnectJwksControllerSpec extends ObjectBehavior
{
    /**
     * @return void
     */
    public function let(JsonWebKeySetService $jsonWebKeySet)
    {
        $this->beConstructedWith($jsonWebKeySet);
    }

    /**
     * @return void
     */
    public function it_is_initializable()
    {
        $this->shouldHaveType(OpenIdConnectJwksController::class);
    }

    /**
     * @return void
     */
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
                'kid' => 'oidc',
                'alg' => 'RS256',
            ],
        ];

        $jsonWebKeySet->keys()->shouldBeCalled()->willReturn($keys);

        $this->__invoke($request)->shouldHavePayload(['keys' => $keys]);
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

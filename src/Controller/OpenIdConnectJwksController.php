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

namespace SimpleSAML\Module\oidc\Controller;

use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequest;

class OpenIdConnectJwksController
{
    /**
     * @var JsonWebKeySetService
     */
    private $jsonWebKeySetService;

    public function __construct(JsonWebKeySetService $jsonWebKeySetService)
    {
        $this->jsonWebKeySetService = $jsonWebKeySetService;
    }

    public function __invoke(ServerRequest $request): JsonResponse
    {
        return new JsonResponse([
            'keys' => array_values($this->jsonWebKeySetService->keys()),
        ]);
    }
}

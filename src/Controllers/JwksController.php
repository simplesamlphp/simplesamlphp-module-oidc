<?php

declare(strict_types=1);

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

namespace SimpleSAML\Module\oidc\Controllers;

use Laminas\Diactoros\Response\JsonResponse;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;
use Symfony\Component\HttpFoundation\Response;

class JwksController
{
    public function __construct(
        private readonly JsonWebKeySetService $jsonWebKeySetService,
        private readonly PsrHttpBridge $psrHttpBridge,
    ) {
    }

    public function __invoke(): JsonResponse
    {
        return new JsonResponse([
            'keys' => array_values($this->jsonWebKeySetService->protocolKeys()),
        ]);
    }

    public function jwks(): Response
    {
        $response = $this->psrHttpBridge->getHttpFoundationFactory()->createResponse($this->__invoke());
        $response->headers->set('Access-Control-Allow-Origin', '*');
        return $response;
    }
}

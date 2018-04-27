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

namespace SimpleSAML\Modules\OpenIDConnect\Controller;

use SimpleSAML\Modules\OpenIDConnect\Services\JsonWebKeySetService;
use Zend\Diactoros\Response\JsonResponse;
use Zend\Diactoros\ServerRequest;

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

    public function jwks(ServerRequest $request)
    {
        return new JsonResponse([
            'keys' => $this->jsonWebKeySetService->keys(),
        ]);
    }
}

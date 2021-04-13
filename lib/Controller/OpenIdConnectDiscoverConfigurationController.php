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

use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Modules\OpenIDConnect\Services\OidcOpenIdProviderMetadataService;

class OpenIdConnectDiscoverConfigurationController
{
    /**
     * @var OidcOpenIdProviderMetadataService
     */
    private $oidcOpenIdProviderMetadataService;

    public function __construct(
        OidcOpenIdProviderMetadataService $oidcOpenIdProviderMetadataService
    ) {
        $this->oidcOpenIdProviderMetadataService = $oidcOpenIdProviderMetadataService;
    }

    public function __invoke(ServerRequest $serverRequest): JsonResponse
    {
        return new JsonResponse($this->oidcOpenIdProviderMetadataService->getMetadata());
    }
}

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

namespace SimpleSAML\Module\oidc\Controller;

use SimpleSAML\Module\oidc\Services\OpMetadataService;
use Symfony\Component\HttpFoundation\JsonResponse;

class ConfigurationDiscoveryController
{
    public function __construct(private readonly OpMetadataService $opMetadataService)
    {
    }

    public function __invoke(): JsonResponse
    {
        return new JsonResponse($this->opMetadataService->getMetadata());
    }
}

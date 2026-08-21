<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers;

use SimpleSAML\Module\oidc\Services\OpMetadataService;
use Symfony\Component\HttpFoundation\JsonResponse;

class ConfigurationDiscoveryController
{
    public function __construct(private readonly OpMetadataService $opMetadataService)
    {
    }

    public function __invoke(): JsonResponse
    {
        return new JsonResponse(
            $this->opMetadataService->getMetadata(),
            headers: ['Access-Control-Allow-Origin' => '*'],
        );
    }
}

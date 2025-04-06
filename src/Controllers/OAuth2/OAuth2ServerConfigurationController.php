<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\OAuth2;

use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\JsonResponse;

class OAuth2ServerConfigurationController
{
    public function __construct(
        protected readonly OpMetadataService $opMetadataService,
        protected readonly Routes $routes,
    ) {
    }

    public function __invoke(): JsonResponse
    {
        // We'll reuse OIDC configuration.
        return $this->routes->newJsonResponse(
            $this->opMetadataService->getMetadata(),
        );

        // TODO mivanci Add ability for claim 'signed_metadata' when moving to simplesamlphp/openid, as per
        // https://www.rfc-editor.org/rfc/rfc8414.html#section-2.1
    }
}

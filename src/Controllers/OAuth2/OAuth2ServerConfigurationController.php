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
        // The OpenID Connect discovery document already carries everything RFC 8414 asks for, the token
        // introspection endpoint included (see OpMetadataService), so it is served here as is, and with the
        // same CORS header, so that a browser-based client can read either document.
        return $this->routes->newJsonResponse(
            $this->opMetadataService->getMetadata(),
            headers: ['Access-Control-Allow-Origin' => '*'],
        );

        // TODO mivanci Add ability for claim 'signed_metadata' when moving to simplesamlphp/openid, as per
        // https://www.rfc-editor.org/rfc/rfc8414.html#section-2.1, with caching support.
    }
}

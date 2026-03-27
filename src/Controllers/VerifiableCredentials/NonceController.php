<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\VerifiableCredentials;

use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\NonceService;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\Response;

class NonceController
{
    public function __construct(
        protected readonly NonceService $nonceService,
        protected readonly Routes $routes,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * @throws \Exception
     */
    public function nonce(): Response
    {
        $this->loggerService->debug('NonceController::nonce');

        $nonce = $this->nonceService->generateNonce();

        return $this->routes->newJsonResponse(
            ['c_nonce' => $nonce],
            200,
            ['Cache-Control' => 'no-store'],
        );
    }
}

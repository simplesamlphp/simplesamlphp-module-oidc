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

namespace SimpleSAML\Module\oidc\Controller\Traits;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

trait RequestTrait
{
    /**
     * Handle CORS 'preflight' requests by checking if 'origin' is registered as allowed to make HTTP CORS requests,
     * typically initiated in browser by JavaScript clients.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function handleCors(ServerRequestInterface $request): ResponseInterface
    {
        $origin = $request->getHeaderLine('Origin');

        if (empty($origin)) {
            throw OidcServerException::requestNotSupported('CORS error: no Origin header present');
        }

        if (! $this->allowedOriginRepository->has($origin)) {
            throw OidcServerException::accessDenied(sprintf('CORS error: origin %s is not allowed', $origin));
        }

        return $this->psrHttpBridge->getResponseFactory()->createResponse(204)
            ->withBody($this->psrHttpBridge->getStreamFactory()->createStream('php://memory'))
            ->withHeader('Access-Control-Allow-Origin', $origin)
            ->withHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            ->withHeader('Access-Control-Allow-Headers', 'Authorization, X-Requested-With')
            ->withHeader('Access-Control-Allow-Credentials', 'true')
        ;
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Traits;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use Symfony\Component\HttpFoundation\Response;

trait RequestTrait
{
    /**
     * Handle CORS 'preflight' requests by checking if 'origin' is registered as allowed to make HTTP CORS requests,
     * typically initiated in browser by JavaScript clients. A `DPoP` request header is allowed along with
     * `Authorization`, for a client which sends a DPoP proof (RFC 9449).
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
            ->withHeader('Access-Control-Allow-Headers', 'Authorization, X-Requested-With, DPoP')
            ->withHeader('Access-Control-Allow-Credentials', 'true')
        ;
    }


    /**
     * The CORS headers of a response to an actual (not a preflight) request, a refusal included: a JavaScript
     * client can read neither the response without `Access-Control-Allow-Origin`, nor, without
     * `Access-Control-Expose-Headers`, its WWW-Authenticate challenge, which RFC 9449 section 7.1 has a server
     * expose to such clients.
     */
    protected function addCorsHeaders(Response $response): Response
    {
        if (!$response->headers->has('Access-Control-Allow-Origin')) {
            $response->headers->set('Access-Control-Allow-Origin', '*');
        }

        $response->headers->set('Access-Control-Expose-Headers', 'WWW-Authenticate');

        return $response;
    }
}

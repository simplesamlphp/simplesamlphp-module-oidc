<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\Traits\RequestTrait;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class AccessTokenController
{
    use RequestTrait;

    public function __construct(
        private readonly AuthorizationServer $authorizationServer,
        private readonly AllowedOriginRepository $allowedOriginRepository,
        private readonly PsrHttpBridge $psrHttpBridge,
        private readonly ErrorResponder $errorResponder,
    ) {
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function __invoke(ServerRequestInterface $request): ResponseInterface
    {
        // Check if this is actually a CORS preflight request...
        if (strtoupper($request->getMethod()) === 'OPTIONS') {
            return $this->handleCors($request);
        }

        return $this->authorizationServer->respondToAccessTokenRequest(
            $request,
            $this->psrHttpBridge->getResponseFactory()->createResponse(),
        );
    }

    public function token(Request $request): Response
    {
        try {
            /**
             * @psalm-suppress DeprecatedMethod Until we drop support for old public/*.php routes, we need to bridge
             * between PSR and Symfony HTTP messages.
             */
            $response = $this->psrHttpBridge->getHttpFoundationFactory()->createResponse(
                $this->__invoke($this->psrHttpBridge->getPsrHttpFactory()->createRequest($request)),
            );

            // If not already handled, allow CORS (for JS clients).
            if (!$response->headers->has('Access-Control-Allow-Origin')) {
                $response->headers->set('Access-Control-Allow-Origin', '*');
            }

            return $response;
        } catch (OAuthServerException $exception) {
            return $this->errorResponder->forException($exception);
        }
    }
}

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
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\DpopProofVerifier;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class AccessTokenController
{
    use RequestTrait;


    public function __construct(
        private readonly AuthorizationServer $authorizationServer,
        private readonly AllowedOriginRepository $allowedOriginRepository,
        private readonly PsrHttpBridge $psrHttpBridge,
        private readonly ErrorResponder $errorResponder,
        private readonly DpopProofVerifier $dpopProofVerifier,
        private readonly Routes $routes,
    ) {
    }


    /**
     * A DPoP proof the request carries is checked first, whatever the grant (RFC 9449 section 5), against the token
     * endpoint URL this OP publishes, and one which fails a check is refused as `invalid_dpop_proof` before any
     * grant runs. The grants read the proof which passed from a request attribute: they bind the tokens they issue
     * to its key, and refuse a code or a refresh token bound to another.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function __invoke(ServerRequestInterface $request): ResponseInterface
    {
        // Check if this is actually a CORS preflight request...
        if (strtoupper($request->getMethod()) === 'OPTIONS') {
            return $this->handleCors($request);
        }

        $verifiedDpopProof = $this->dpopProofVerifier->verify($request, $this->routes->urlToken(), null);
        if ($verifiedDpopProof !== null) {
            $request = $request->withAttribute(DpopProofVerifier::ATTRIBUTE_VERIFIED_PROOF, $verifiedDpopProof);
        }

        // A token request is read as it was sent: a request or request_uri param in it is ignored, rather than read
        // as an authorization request's (RFC 6749 section 3.2).
        $request = $request->withAttribute(RequestParamsResolver::ATTRIBUTE_OWN_PARAMS_ONLY, true);

        return $this->authorizationServer->respondToAccessTokenRequest(
            $request,
            $this->psrHttpBridge->getResponseFactory()->createResponse(),
        );
    }


    /**
     * The CORS headers go on a refusal too, so that a JavaScript client can read why it was refused; not on the
     * refusal of a preflight, which no header can make pass.
     */
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
        } catch (OAuthServerException $exception) {
            $response = $this->errorResponder->forException($exception);
        } catch (Throwable $exception) {
            // A failure of the OP's own - a database or cache which did not answer while the client was being
            // authenticated or the grant redeemed - is answered as `server_error` in the token error format,
            // rather than left to SimpleSAMLphp's HTML error page. The client is told nothing of the cause; the
            // ErrorResponder logs it.
            $response = $this->errorResponder->forException(
                OidcServerException::serverError('Unable to process the token request.', $exception),
            );
        }

        if ($response->getStatusCode() >= 400 && strtoupper($request->getMethod()) === 'OPTIONS') {
            return $response;
        }

        // If not already handled, allow CORS (for JS clients).
        return $this->addCorsHeaders($response);
    }
}

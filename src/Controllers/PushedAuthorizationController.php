<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AuthorizationDetailsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\DpopJktRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IssuerStateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\OfferedCredentialsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\Validators\DpopProofVerifier;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\VerifiedDpopProof;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

use function hash_equals;

class PushedAuthorizationController
{
    public function __construct(
        private readonly AuthenticatedOAuth2ClientResolver $authenticatedOAuth2ClientResolver,
        private readonly PushedAuthorizationRequestRepository $pushedAuthorizationRequestRepository,
        private readonly PushedAuthorizationRequestEntityFactory $pushedAuthorizationRequestEntityFactory,
        private readonly RequestRulesManager $requestRulesManager,
        private readonly PsrHttpBridge $psrHttpBridge,
        private readonly ErrorResponder $errorResponder,
        private readonly Helpers $helpers,
        private readonly LoggerService $logger,
        private readonly DpopProofVerifier $dpopProofVerifier,
        private readonly Routes $routes,
    ) {
    }


    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Throwable
     */
    public function __invoke(ServerRequestInterface $request): ResponseInterface
    {
        $this->logger->debug('PushedAuthorizationController::__invoke');

        if (strtoupper($request->getMethod()) !== HttpMethodsEnum::POST->value) {
            return $this->psrHttpBridge->getResponseFactory()->createResponse()
                ->withStatus(405)
                ->withHeader('Allow', HttpMethodsEnum::POST->value);
        }

        // Authenticate the client in the same way as at the token endpoint.
        $resolvedAuth = $this->authenticatedOAuth2ClientResolver->forAnySupportedMethod($request);
        if (is_null($resolvedAuth)) {
            throw OidcServerException::accessDenied('Client authentication failed.');
        }

        $client = $resolvedAuth->getClient();

        if ($resolvedAuth->getClientAuthenticationMethod()->isNone() && $client->isConfidential()) {
            throw OidcServerException::accessDenied('Confidential client must authenticate.');
        }

        $bodyParams = $request->getParsedBody();
        $bodyParams = is_array($bodyParams) ? $bodyParams : [];

        // The request_uri authorization request parameter must not be used in pushed authorization requests.
        if (array_key_exists(ParamsEnum::RequestUri->value, $bodyParams)) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'The request_uri parameter must not be used in pushed authorization requests.',
            );
        }

        // A DPoP proof the pushed request carries is checked as at the token endpoint, against this endpoint's
        // published URL; its key binds the authorization code (RFC 9449 section 10.1, withProvenDpopKey()).
        $verifiedDpopProof = $this->dpopProofVerifier->verify(
            $request,
            $this->routes->urlPushedAuthorizationRequest(),
            null,
        );

        // Validate the pushed params as we would an authorization request sent to the authorization endpoint.
        // Note that the rules transparently take the Request Object (request param) into account, with
        // RequestObjectRule doing its validation (signature, signed-required policy...).
        $resultBag = new ResultBag();
        $resultBag->add(new Result(ClientRule::class, $client));
        $this->requestRulesManager->predefineResultBag($resultBag);

        $this->requestRulesManager->setData('default_scope', '');
        $this->requestRulesManager->setData('scope_delimiter_string', ' ');

        $rulesToExecute = [
            StateRule::class,
            ClientRedirectUriRule::class,
            RequestObjectRule::class,
            ResponseModeRule::class,
            ScopeRule::class,
            RequiredOpenIdScopeRule::class,
            CodeChallengeRule::class,
            CodeChallengeMethodRule::class,
            DpopJktRule::class,
            // A pushed request following a Credential Offer is refused here when its offer can no longer be
            // redeemed, or when it asks for a credential configuration the offer did not offer, rather than only
            // once the End-User has logged in.
            IssuerStateRule::class,
            AuthorizationDetailsRule::class,
            OfferedCredentialsRule::class,
        ];

        $resultBag = $this->requestRulesManager->check(
            $request,
            $rulesToExecute,
            new QueryResponseMode(),
            [HttpMethodsEnum::POST],
        );

        $parameters = $this->resolveParametersToPersist($resultBag, $bodyParams, $client->getIdentifier());
        $parameters = $this->withProvenDpopKey($parameters, $resultBag, $verifiedDpopProof);

        $parEntity = $this->pushedAuthorizationRequestEntityFactory->fromData(
            $client->getIdentifier(),
            $parameters,
        );

        $this->pushedAuthorizationRequestRepository->persist($parEntity);

        $responseBody = json_encode(
            [
                'request_uri' => $parEntity->getRequestUri(),
                'expires_in' => $this->helpers->dateTime()->getSecondsToExpirationTime(
                    $parEntity->getExpiresAt()->getTimestamp(),
                ),
            ],
            JSON_THROW_ON_ERROR,
        );

        $response = $this->psrHttpBridge->getResponseFactory()->createResponse()
            ->withStatus(201)
            ->withHeader('Cache-Control', 'no-cache, no-store')
            ->withHeader('Content-Type', 'application/json');

        $response->getBody()->write($responseBody);

        return $response;
    }


    /**
     * Resolve the authorization request parameters which are to be persisted
     * for later use at the authorization endpoint.
     *
     * @param mixed[] $bodyParams
     * @return mixed[]
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function resolveParametersToPersist(
        ResultBagInterface $resultBag,
        array $bodyParams,
        string $clientId,
    ): array {
        // If a body client_id param was provided, it must match the authenticated client.
        if (
            array_key_exists(ParamsEnum::ClientId->value, $bodyParams) &&
            $bodyParams[ParamsEnum::ClientId->value] !== $clientId
        ) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::ClientId->value,
                'The client_id parameter does not match the authenticated client.',
            );
        }

        // Make sure not to persist client authentication related params (they are not part of the authorization
        // request itself).
        $parameters = $bodyParams;
        unset(
            $parameters[ParamsEnum::ClientSecret->value],
            $parameters[ParamsEnum::ClientAssertion->value],
            $parameters[ParamsEnum::ClientAssertionType->value],
        );

        if ($resultBag->get(RequestObjectRule::class) !== null) {
            // Request Object (JAR) was used. RFC 9126 section 3 has every authorization request parameter appear as
            // a claim of it, but the rules validated it together with the form body, its claims superseding form
            // parameters of the same name, the way a Request Object is read at the authorization endpoint
            // (RequestParamsResolver). That is what is persisted: a pushed request is redeemed with its persisted
            // parameters only, so a parameter validated here and not persisted would be lost.
            $requestObjectParameters = $resultBag->getOrFail(RequestObjectRule::class)->getValue();

            /** @psalm-suppress MixedAssignment */
            $clientIdClaim = $requestObjectParameters[ParamsEnum::ClientId->value] ?? null;
            if (!is_null($clientIdClaim) && $clientIdClaim !== $clientId) {
                throw OidcServerException::invalidRequest(
                    ParamsEnum::ClientId->value,
                    'The client_id claim in request object does not match the authenticated client.',
                );
            }

            $parameters = array_merge($parameters, $requestObjectParameters);
        }

        unset(
            $parameters[ParamsEnum::Request->value],
            $parameters[ParamsEnum::RequestUri->value],
        );

        // Bind the parameters to the authenticated client.
        $parameters[ParamsEnum::ClientId->value] = $clientId;

        // A pushed request is redeemed with its persisted parameters only (RequestParamsResolver), so one without a
        // response_type could never be: it is refused here rather than at the authorization endpoint.
        if (!isset($parameters[ParamsEnum::ResponseType->value])) {
            $this->logger->notice('Pushed authorization request rejected: `response_type` parameter not provided.');
            throw OidcServerException::invalidRequest(ParamsEnum::ResponseType->value, 'Missing response_type');
        }

        // The scope decides whether the request is an OpenID Connect one, so the one the request was validated with
        // (ScopeRule) is always persisted: a request pushed without one, a plain OAuth 2.0 or an OpenID4VCI request,
        // gets an empty one, rather than none, which would leave its scope to the default scope of the grant at the
        // authorization endpoint.
        if (!isset($parameters[ParamsEnum::Scope->value])) {
            $validatedScopes = $resultBag->getOrFail(ScopeRule::class)->getValue();
            $parameters[ParamsEnum::Scope->value] = implode(
                ' ',
                array_map(static fn(ScopeEntityInterface $scope): string => $scope->getIdentifier(), $validatedScopes),
            );
        }

        return $parameters;
    }


    /**
     * The parameters to persist, with the key of the pushed request's DPoP proof, if it carried one, as `dpop_jkt`:
     * the authorization endpoint then binds the code to that key as if the client had sent the parameter (RFC 9449
     * section 10.1). A request which also sends `dpop_jkt`, naming another key, contradicts itself and is refused
     * as `invalid_request`.
     *
     * @param mixed[] $parameters
     * @return mixed[]
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function withProvenDpopKey(
        array $parameters,
        ResultBagInterface $resultBag,
        ?VerifiedDpopProof $verifiedDpopProof,
    ): array {
        if ($verifiedDpopProof === null) {
            return $parameters;
        }

        $proofJkt = $verifiedDpopProof->getJwkThumbprint();
        $dpopJkt = $resultBag->getOrFail(DpopJktRule::class)->getValue();

        if ($dpopJkt !== null && !hash_equals($dpopJkt, $proofJkt)) {
            $this->logger->notice(
                'Pushed authorization request rejected: `dpop_jkt` names another key than the DPoP proof.',
            );
            throw OidcServerException::invalidRequest(
                ClaimsEnum::DpopJkt->value,
                'The dpop_jkt parameter names another key than the DPoP proof of the request.',
            );
        }

        $parameters[ClaimsEnum::DpopJkt->value] = $proofJkt;

        return $parameters;
    }


    public function par(Request $request): Response
    {
        try {
            $psrRequest = $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request);
            $psrResponse = $this->__invoke($psrRequest);
            return $this->psrHttpBridge->getHttpFoundationFactory()->createResponse($psrResponse);
        } catch (OAuthServerException $exception) {
            // Per RFC 9126, the error response format is the one specified for the token endpoint, so make
            // sure we never redirect (regardless of any redirect URI contained in the exception).
            return $this->errorResponder->forExceptionJson($exception);
        } catch (Throwable $exception) {
            $this->logger->error(
                'PushedAuthorizationController: error processing request: ' . $exception->getMessage(),
            );
            return $this->errorResponder->forExceptionJson(
                OidcServerException::serverError('Unable to process pushed authorization request.'),
            );
        }
    }
}

<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2026 by the Spanish Research and Academic Network.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Controllers;

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
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

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
        ];

        $resultBag = $this->requestRulesManager->check(
            $request,
            $rulesToExecute,
            new QueryResponseMode(),
            [HttpMethodsEnum::POST],
        );

        $parameters = $this->resolveParametersToPersist($resultBag, $bodyParams, $client->getIdentifier());

        $parEntity = $this->pushedAuthorizationRequestEntityFactory->buildNew(
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
     * Resolve the authorization request parameters which are to be persisted for later use at the
     * authorization endpoint.
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

        $requestObjectResult = $resultBag->get(RequestObjectRule::class);

        if ($requestObjectResult !== null) {
            // Request Object (JAR) was used. Per RFC 9126, all authorization request parameters must appear
            // as claims of the Request Object, so only use its (validated) payload.
            /** @psalm-suppress MixedAssignment */
            $parameters = $resultBag->getOrFail(RequestObjectRule::class)->getValue();
            $parameters = is_array($parameters) ? $parameters : [];

            /** @psalm-suppress MixedAssignment */
            $clientIdClaim = $parameters[ParamsEnum::ClientId->value] ?? null;
            if (!is_null($clientIdClaim) && $clientIdClaim !== $clientId) {
                throw OidcServerException::invalidRequest(
                    ParamsEnum::ClientId->value,
                    'The client_id claim in request object does not match the authenticated client.',
                );
            }
        } else {
            // Plain pushed authorization request. Make sure not to persist client authentication related
            // params (they are not part of the authorization request itself).
            $parameters = $bodyParams;
            unset(
                $parameters[ParamsEnum::ClientSecret->value],
                $parameters[ParamsEnum::ClientAssertion->value],
                $parameters[ParamsEnum::ClientAssertionType->value],
            );
        }

        unset(
            $parameters[ParamsEnum::Request->value],
            $parameters[ParamsEnum::RequestUri->value],
        );

        // Bind the parameters to the authenticated client.
        $parameters[ParamsEnum::ClientId->value] = $clientId;

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
        } catch (\Throwable $exception) {
            $this->logger->error(
                'PushedAuthorizationController: error processing request: ' . $exception->getMessage(),
            );
            return $this->errorResponder->forExceptionJson(
                OidcServerException::serverError('Unable to process pushed authorization request.'),
            );
        }
    }
}

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
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\RequestObject;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class PushedAuthorizationController
{
    public function __construct(
        private readonly AuthenticatedOAuth2ClientResolver $authenticatedOAuth2ClientResolver,
        private readonly PushedAuthorizationRequestRepository $pushedAuthorizationRequestRepository,
        private readonly RequestRulesManager $requestRulesManager,
        private readonly JwksResolver $jwksResolver,
        private readonly RequestObject $requestObject,
        private readonly ModuleConfig $moduleConfig,
        private readonly PsrHttpBridge $psrHttpBridge,
        private readonly ErrorResponder $errorResponder,
        private readonly Helpers $helpers,
        private readonly LoggerService $logger,
    ) {
    }

    public function __invoke(ServerRequestInterface $request): ResponseInterface
    {
        $this->logger->debug('PushedAuthorizationController::__invoke');

        if (strtoupper($request->getMethod()) !== 'POST') {
            return $this->psrHttpBridge->getResponseFactory()->createResponse()
                ->withStatus(405)
                ->withHeader('Allow', 'POST');
        }

        // 1. Authenticate client
        $resolvedAuth = $this->authenticatedOAuth2ClientResolver->forAnySupportedMethod($request);
        if (is_null($resolvedAuth)) {
            throw OidcServerException::accessDenied('Client authentication failed');
        }

        $client = $resolvedAuth->getClient();

        if ($resolvedAuth->getClientAuthenticationMethod()->isNone() && $client->isConfidential()) {
            throw OidcServerException::accessDenied('Confidential client must authenticate.');
        }

        // 2. Parse request params
        $bodyParams = $request->getParsedBody();
        $params = is_array($bodyParams) ? $bodyParams : [];

        // 3. Reject request_uri in PAR body
        if (isset($params['request_uri'])) {
            throw OidcServerException::invalidRequest(
                'request_uri',
                'The request_uri parameter MUST NOT be provided in pushed authorization requests.',
            );
        }

        // 4. Handle JAR in PAR (request parameter)
        if (isset($params['request'])) {
            try {
                $requestObject = $this->requestObject->jarRequestObjectFactory()->fromToken((string)$params['request']);
                $jwks = $this->jwksResolver->forClient($client);
                if (is_null($jwks)) {
                    throw OidcServerException::invalidRequest(
                        'request',
                        'Client JWKS not available for signature verification.',
                    );
                }
                $requestObject->verifyWithKeySet($jwks);

                if ($requestObject->getClientId() !== $client->getIdentifier()) {
                    throw OidcServerException::invalidRequest(
                        'request',
                        'Client ID in request object does not match authenticated client.',
                    );
                }

                $params = array_merge($params, $requestObject->getPayload());
                unset($params['request']);
            } catch (\Throwable $t) {
                throw OidcServerException::invalidRequest('request', 'Invalid request object: ' . $t->getMessage());
            }
        }

        // 5. Build mock request with merged params and run validation rules
        $psrRequest = $request->withParsedBody($params)->withQueryParams([]);

        $resultBag = new ResultBag();
        $resultBag->add(new Result(ClientRule::class, $client));

        $this->requestRulesManager->predefineResultBag($resultBag);

        $rulesToExecute = [
            StateRule::class,
            ClientRedirectUriRule::class,
            ResponseModeRule::class,
            ScopeRule::class,
            RequiredOpenIdScopeRule::class,
            CodeChallengeRule::class,
            CodeChallengeMethodRule::class,
        ];

        $this->requestRulesManager->setData('default_scope', '');
        $this->requestRulesManager->setData('scope_delimiter_string', ' ');

        $this->requestRulesManager->check(
            $psrRequest,
            $rulesToExecute,
            new QueryResponseMode(),
            [HttpMethodsEnum::POST],
        );

        // 6. Generate request_uri
        $hex = bin2hex(random_bytes(32));
        $requestUri = 'urn:ietf:params:oauth:request_uri:' . $hex;

        // 7. Persist entity
        $ttl = $this->moduleConfig->getParRequestUriTtl();
        $expiresAt = $this->helpers->dateTime()->getUtc()->add($ttl);

        // Make sure we carry forward all validated params
        $entity = new PushedAuthorizationRequestEntity(
            requestUri: $requestUri,
            clientId: $client->getIdentifier(),
            parameters: $params,
            expiresAt: \DateTimeImmutable::createFromInterface($expiresAt),
            isConsumed: false,
        );

        $this->pushedAuthorizationRequestRepository->persist($entity);

        // 8. Respond
        $expiresIn = $this->helpers->dateTime()->getSecondsToExpirationTime($expiresAt->getTimestamp());
        $responseBody = json_encode([
            'request_uri' => $requestUri,
            'expires_in' => $expiresIn,
        ], JSON_THROW_ON_ERROR);

        $response = $this->psrHttpBridge->getResponseFactory()->createResponse()
            ->withStatus(201)
            ->withHeader('Cache-Control', 'no-cache, no-store')
            ->withHeader('Content-Type', 'application/json');

        $response->getBody()->write($responseBody);

        return $response;
    }

    public function par(Request $request): Response
    {
        try {
            $psrRequest = $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request);
            $psrResponse = $this->__invoke($psrRequest);
            return $this->psrHttpBridge->getHttpFoundationFactory()->createResponse($psrResponse);
        } catch (OAuthServerException $exception) {
            return $this->errorResponder->forException($exception);
        } catch (\Throwable $exception) {
            return $this->errorResponder->forException(
                OidcServerException::invalidRequest('request', $exception->getMessage()),
            );
        }
    }
}

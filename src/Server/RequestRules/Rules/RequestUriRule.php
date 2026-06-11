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

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core\RequestObject as ConnectRequestObject;
use SimpleSAML\OpenID\Jar\RequestObject as JarRequestObject;

/**
 * Handle the request_uri authorization request parameter:
 *  - Pushed Authorization Request URIs (RFC 9126, urn form): validate existence, expiration, one-time use
 *    (consume on validation) and client binding,
 *  - https Request URIs (RFC 9101 / OpenID Connect Core, Request Object by reference): validate that the
 *    Request URI is registered for the client, and validate the fetched Request Object (signature, client
 *    binding), differentiating between OpenID Connect and plain OAuth 2.0 (JAR) requests,
 *  - enforce Pushed Authorization Request usage if required by server or client policy.
 *
 * Note that the actual resolution of params from the request_uri value is done in RequestParamsResolver, so
 * that resolved params are transparently available to all other rules.
 *
 * @see \SimpleSAML\Module\oidc\Utils\RequestParamsResolver
 */
class RequestUriRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected PushedAuthorizationRequestRepository $pushedAuthorizationRequestRepository,
        protected JwksResolver $jwksResolver,
        protected ModuleConfig $moduleConfig,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     *
     * @param ResponseModeInterface $responseMode
     * @param HttpMethodsEnum[] $allowedServerRequestMethods
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface {
        $loggerService->debug('RequestUriRule::checkRule');

        // Note: we are intentionally working with raw request params here
        // (not the merged view which includes params resolved from the
        // request_uri itself).
        $requestUri = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::RequestUri->value,
            $request,
            $allowedServerRequestMethods,
        );

        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();

        $isParRequired = $this->moduleConfig->getRequirePushedAuthorizationRequests() ||
        $client->getRequirePushedAuthorizationRequests();

        if (is_null($requestUri) || $requestUri === '') {
            if ($isParRequired) {
                throw OidcServerException::invalidRequest(
                    ParamsEnum::RequestUri->value,
                    'Pushed Authorization Request (PAR) is required.',
                );
            }

            return null;
        }

        $requestParam = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::Request->value,
            $request,
            $allowedServerRequestMethods,
        );

        if (!is_null($requestParam)) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'Params request and request_uri must not be used together.',
            );
        }

        $clientIdParam = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::ClientId->value,
            $request,
            $allowedServerRequestMethods,
        );

        if (is_null($clientIdParam) || $clientIdParam === '') {
            throw OidcServerException::invalidRequest(
                ParamsEnum::ClientId->value,
                'Param client_id is required when using request_uri.',
            );
        }

        if (str_starts_with($requestUri, PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX)) {
            return $this->checkPushedAuthorizationRequestUri(
                $requestUri,
                $clientIdParam,
                $client,
                $loggerService,
            );
        }

        if (str_starts_with(strtolower($requestUri), 'https://')) {
            return $this->checkHttpsRequestUri(
                $requestUri,
                $client,
                $request,
                $currentResultBag,
                $isParRequired,
                $allowedServerRequestMethods,
            );
        }

        throw OidcServerException::invalidRequest(
            ParamsEnum::RequestUri->value,
            'Invalid request_uri scheme / format.',
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    protected function checkPushedAuthorizationRequestUri(
        string $requestUri,
        string $clientIdParam,
        ClientEntityInterface $client,
        LoggerService $loggerService,
    ): ResultInterface {
        $parEntity = $this->pushedAuthorizationRequestRepository->find($requestUri);

        if ($parEntity === null) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'Pushed authorization request not found.',
            );
        }

        if ($parEntity->isExpired($this->helpers->dateTime()->getUtc())) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'Pushed authorization request has expired.',
            );
        }

        if ($parEntity->isConsumed()) {
            $loggerService->warning(
                'RequestUriRule: pushed authorization request replay attempt.',
                compact('requestUri'),
            );
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'Pushed authorization request has already been used.',
            );
        }

        // The request_uri value must be bound to the client that posted the authorization request.
        if (
            $parEntity->getClientId() !== $clientIdParam ||
            $parEntity->getClientId() !== $client->getIdentifier()
        ) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::ClientId->value,
                'Pushed authorization request is bound to different client.',
            );
        }

        // Request URIs are one-time use. Consume it now (atomically, to prevent concurrent replays).
        if (!$this->pushedAuthorizationRequestRepository->consume($requestUri)) {
            $loggerService->warning(
                'RequestUriRule: pushed authorization request concurrent consumption attempt.',
                compact('requestUri'),
            );
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'Pushed authorization request has already been used.',
            );
        }

        return new Result($this->getKey(), $requestUri);
    }

    /**
     * @param HttpMethodsEnum[] $allowedServerRequestMethods
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    protected function checkHttpsRequestUri(
        string $requestUri,
        ClientEntityInterface $client,
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        bool $isParRequired,
        array $allowedServerRequestMethods,
    ): ResultInterface {
        if ($isParRequired) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'Pushed Authorization Request (PAR) is required.',
            );
        }

        if (!in_array($requestUri, $client->getRequestUris(), true)) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'The request_uri is not registered for this client.',
            );
        }

        // Make sure the request_uri resolution ran (it is memoized in
        // RequestParamsResolver, so this is inexpensive if other rules already
        // triggered it), then grab the resolved Request Object Bag.
        $this->requestParamsResolver->getAllBasedOnAllowedMethods($request, $allowedServerRequestMethods);

        $requestObjectBag = $this->requestParamsResolver->getResolvedRequestUriBag($requestUri);
        if ($requestObjectBag === null) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'Could not fetch or parse the Request Object from request_uri.',
            );
        }

        if (!$this->isOidcAuthorizationRequest($request, $allowedServerRequestMethods)) {
            // This is a plain OAuth 2.0 authorization request, so JAR
            // (RFC 9101) rules apply: the Request Object must be a signed
            // JWT containing the Client ID claim.
            $requestObject = $requestObjectBag->get(JarRequestObject::class);
            if (!$requestObject instanceof JarRequestObject) {
                throw OidcServerException::invalidRequest(
                    ParamsEnum::RequestUri->value,
                    'Request object is not a valid JAR Request Object (note that it must be signed).',
                );
            }

            $this->verifySignature($requestObject, $client);
        } else {
            // This is an OpenID Connect authorization request, so OpenID Connect Core rules apply: the
            // Request Object can be unsigned (unless signature is required by policy).
            $requestObject = $requestObjectBag->get(ConnectRequestObject::class);
            if (!$requestObject instanceof ConnectRequestObject) {
                throw OidcServerException::invalidRequest(
                    ParamsEnum::RequestUri->value,
                    'Request object is not a valid Request Object.',
                );
            }

            if ($requestObject->isProtected()) {
                $this->verifySignature($requestObject, $client);
            } elseif (
                $this->moduleConfig->getRequireSignedRequestObject() ||
                $client->getRequireSignedRequestObject()
            ) {
                throw OidcServerException::invalidRequest(
                    ParamsEnum::RequestUri->value,
                    'Request object must be signed (alg: none is not allowed).',
                );
            }
        }

        $payload = $requestObject->getPayload();

        /** @psalm-suppress MixedAssignment */
        $clientIdClaim = $payload[ParamsEnum::ClientId->value] ?? null;
        if ($clientIdClaim !== $client->getIdentifier()) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'Client ID claim in request object does not match the client_id parameter.',
            );
        }

        // Mark the Request Object as resolved (and validated), so that RequestObjectRule does not need to
        // run again for it.
        $currentResultBag->add(new Result(RequestObjectRule::class, $payload));

        return new Result($this->getKey(), $requestUri);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function verifySignature(
        ConnectRequestObject|JarRequestObject $requestObject,
        ClientEntityInterface $client,
    ): void {
        ($jwks = $this->jwksResolver->forClient($client)) || throw OidcServerException::accessDenied(
            'can not validate request object, client JWKS not available',
        );

        try {
            $requestObject->verifyWithKeySet($jwks);
        } catch (\Throwable $exception) {
            throw OidcServerException::accessDenied(
                'request object validation failed: ' . $exception->getMessage(),
            );
        }
    }
}

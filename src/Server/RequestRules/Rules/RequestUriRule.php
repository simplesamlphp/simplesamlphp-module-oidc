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
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * Gatekeeper for the request_uri authorization request parameter. It does not
 * parse, fetch, or verify the Request Object itself (that is the job of the
 * RequestParamsResolver and the RequestObjectRule); it only enforces
 *  the request_uri usage policy:
 *  - request and request_uri must not be used together (RFC 9101),
 *  - client_id is required when using request_uri,
 *  - Pushed Authorization Request URIs (RFC 9126, urn form): existence,
 *    expiration, one-time use (consume on validation) and client binding,
 *  - https Request URIs (Request Object by reference): the OP must support
 *    the request_uri parameter, and the Request Object must be resolvable
 *    (registration / federation policy is enforced in RequestParamsResolver),
 *  - Pushed Authorization Request usage if required by server or client policy.
 *
 * @see \SimpleSAML\Module\oidc\Utils\RequestParamsResolver
 * @see \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule
 */
class RequestUriRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected PushedAuthorizationRequestRepository $pushedAuthorizationRequestRepository,
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
                $request,
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

        // The request_uri value must be bound to the client that posted
        // authorization request.
        if (
            $parEntity->getClientId() !== $clientIdParam ||
            $parEntity->getClientId() !== $client->getIdentifier()
        ) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::ClientId->value,
                'Pushed authorization request is bound to different client.',
            );
        }

        // Request URIs are one-time use. Consume it now (atomically, to prevent
        // concurrent replays).
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
        ServerRequestInterface $request,
        bool $isParRequired,
        array $allowedServerRequestMethods,
    ): ResultInterface {
        if ($isParRequired) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'Pushed Authorization Request (PAR) is required.',
            );
        }

        if (!$this->moduleConfig->getRequestUriParameterSupported()) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'Passing the request object by reference (request_uri) is not supported.',
            );
        }

        // Make sure the Request Object behind the request_uri can actually be
        // resolved (fetched and parsed, and allowed by registration /
        // federation policy in RequestParamsResolver). The signature and other
        // request object validations are then done by the RequestObjectRule
        // (or by ClientRule for the federation case).
        $requestObjectBag = $this->requestParamsResolver->getRequestObjectBag($request, $allowedServerRequestMethods);
        if ($requestObjectBag === null) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::RequestUri->value,
                'The request_uri could not be resolved (it may not be allowed for this client, or the fetch ' .
                'failed).',
            );
        }

        return new Result($this->getKey(), $requestUri);
    }
}

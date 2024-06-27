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

namespace SimpleSAML\Module\oidc\Controller;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthorizationController
{
    public function __construct(
        private readonly AuthenticationService $authenticationService,
        private readonly AuthorizationServer $authorizationServer,
        private readonly ModuleConfig $moduleConfig,
        private readonly LoggerService $loggerService,
        private readonly PsrHttpBridge $psrHttpBridge,
        private readonly ErrorResponder $errorResponder,
    ) {
    }

    /**
     * @throws \Exception
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Error\Exception
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Throwable
     *
     * @deprecated 7.0.0 Will be moved to Symfony controller method
     * @see self::authorization()
     */
    public function __invoke(ServerRequestInterface $request): ResponseInterface
    {
        $queryParameters = $request->getQueryParams();
        $state = null;

        if (!isset($queryParameters[ProcessingChain::AUTHPARAM])) {
            $authorizationRequest = $this->authorizationServer->validateAuthorizationRequest($request);
            $state = $this->authenticationService->processRequest($request, $authorizationRequest);
            // processState will trigger a redirect
        }

        $state ??= $this->authenticationService->loadState($queryParameters);
        $authorizationRequest = $this->authenticationService->getAuthorizationRequestFromState($state);

        $user = $this->authenticationService->getAuthenticateUser($state);

        $authorizationRequest->setUser($user);
        $authorizationRequest->setAuthorizationApproved(true);

        $authorizationRequest->setIsCookieBasedAuthn($this->authenticationService->isCookieBasedAuthn());
        $authorizationRequest->setAuthSourceId($this->authenticationService->getAuthSourceId());
        $authorizationRequest->setSessionId($this->authenticationService->getSessionId());

        $this->validatePostAuthnAuthorizationRequest($authorizationRequest);

        return $this->authorizationServer->completeAuthorizationRequest(
            $authorizationRequest,
            $this->psrHttpBridge->getResponseFactory()->createResponse(),
        );
    }

    /**
     * @param   Request  $request
     *
     * @return Response
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Error
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\NotFound
     * @throws \Throwable
     */
    public function authorization(Request $request): Response
    {
        try {
            /**
             * @psalm-suppress DeprecatedMethod Until we drop support for old public/*.php routes, we need to bridge
             * between PSR and Symfony HTTP messages.
             */
            return $this->psrHttpBridge->getHttpFoundationFactory()->createResponse(
                $this->__invoke($this->psrHttpBridge->getPsrHttpFactory()->createRequest($request)),
            );
        } catch (OAuthServerException $exception) {
            return $this->errorResponder->forException($exception);
        }
    }

    /**
     * Validate authorization request after the authn has been performed. For example, check if the
     * ACR claim has been requested and that authn performed satisfies it.
     *
     * @throws \Exception
     */
    protected function validatePostAuthnAuthorizationRequest(AuthorizationRequest $authorizationRequest): void
    {
        $this->validateAcr($authorizationRequest);
    }

    /**
     * @throws \Exception
     */
    protected function validateAcr(AuthorizationRequest $authorizationRequest): void
    {
        // If no ACRs requested, don't set ACR claim.
        if (($requestedAcrValues = $authorizationRequest->getRequestedAcrValues()) === null) {
            return;
        }

        // In order to check available ACRs, we have to know auth source and if authn was based on cookie.
        if (($authSourceId = $authorizationRequest->getAuthSourceId()) === null) {
            throw OidcServerException::serverError('authSourceId not set on authz request');
        }
        if (($isCookieBasedAuthn = $authorizationRequest->getIsCookieBasedAuthn()) === null) {
            throw OidcServerException::serverError('isCookieBasedAuthn not set on authz request');
        }

        $authSourceToAcrValuesMap = $this->moduleConfig->getAuthSourcesToAcrValuesMap();

        $availableAuthSourceAcrs = is_array($authSourceToAcrValuesMap[$authSourceId]) ?
        $authSourceToAcrValuesMap[$authSourceId] :
        [];
        $forcedAcrForCookieAuthentication = $this->moduleConfig->getForcedAcrValueForCookieAuthentication();

        if ($forcedAcrForCookieAuthentication !== null && $isCookieBasedAuthn) {
            $availableAuthSourceAcrs = [$forcedAcrForCookieAuthentication];
        }

        $isRequestedAcrEssential = empty($requestedAcrValues['essential']) ?
        false :
        boolval($requestedAcrValues['essential']);

        $acrs = !empty($requestedAcrValues['values']) && is_array($requestedAcrValues['values']) ?
        $requestedAcrValues['values'] :
        [];

        $matchedAcrs = array_intersect($availableAuthSourceAcrs, $acrs);

        // If we have matched ACRs, use the best (first) one (order is important).
        if (!empty($matchedAcrs)) {
            $authorizationRequest->setAcr((string)current($matchedAcrs));
            return;
        }

        // Since we don't have matched ACRs, and the client marked the requested claim as essential, error out.
        if ($isRequestedAcrEssential) {
            throw OidcServerException::accessDenied('could not satisfy requested ACR');
        }

        // If the ACR is not essential, we should return current session ACR (if we have one available)...
        if (! empty($availableAuthSourceAcrs)) {
            $authorizationRequest->setAcr((string)current($availableAuthSourceAcrs));
            return;
        }

        // ...according to spec we have to return acr claim, and we don't have one available (none configured)...
        $genericAcr = 'N/A';
        $message = sprintf(
            'No ACRs configured for current auth source, whilst specification mandates one. ' .
            'Falling back to generic ACR (%s).',
            $genericAcr,
        );
        $this->loggerService->warning($message);
        $authorizationRequest->setAcr($genericAcr);
    }
}

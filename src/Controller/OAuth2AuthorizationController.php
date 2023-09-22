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

use Exception;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Error;
use SimpleSAML\Module\oidc\ConfigurationService;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use Throwable;

class OAuth2AuthorizationController
{
    public function __construct(
        private readonly AuthenticationService $authenticationService,
        private readonly AuthorizationServer $authorizationServer,
        private readonly ConfigurationService $configurationService,
        private readonly LoggerService $loggerService
    ) {
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\NotFound
     * @throws Error\Exception
     * @throws OAuthServerException
     * @throws Exception|Throwable
     */
    public function __invoke(ServerRequest $request): ResponseInterface
    {
        $authorizationRequest = $this->authorizationServer->validateAuthorizationRequest($request);

        $user = $this->authenticationService->getAuthenticateUser($request);

        $authorizationRequest->setUser($user);
        $authorizationRequest->setAuthorizationApproved(true);

        if ($authorizationRequest instanceof AuthorizationRequest) {
            $authorizationRequest->setIsCookieBasedAuthn($this->authenticationService->isCookieBasedAuthn());
            $authorizationRequest->setAuthSourceId($this->authenticationService->getAuthSourceId());
            $authorizationRequest->setSessionId($this->authenticationService->getSessionId());

            $this->validatePostAuthnAuthorizationRequest($authorizationRequest);
        }

        return $this->authorizationServer->completeAuthorizationRequest($authorizationRequest, new Response());
    }

    /**
     * Validate authorization request after the authn has been performed. For example, check if the
     * ACR claim has been requested and that authn performed satisfies it.
     * @throws Exception
     */
    protected function validatePostAuthnAuthorizationRequest(AuthorizationRequest &$authorizationRequest): void
    {
        $this->validateAcr($authorizationRequest);
    }

    /**
     * @throws Exception
     */
    protected function validateAcr(AuthorizationRequest &$authorizationRequest): void
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

        $authSourceToAcrValuesMap = $this->configurationService->getAuthSourcesToAcrValuesMap();

        $availableAuthSourceAcrs = is_array($authSourceToAcrValuesMap[$authSourceId]) ?
            $authSourceToAcrValuesMap[$authSourceId] :
            [];
        $forcedAcrForCookieAuthentication = $this->configurationService->getForcedAcrValueForCookieAuthentication();

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
            $genericAcr
        );
        $this->loggerService->warning($message);
        $authorizationRequest->setAcr($genericAcr);
    }
}

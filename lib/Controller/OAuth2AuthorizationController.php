<?php

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

use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

use function PHPUnit\Framework\throwException;

class OAuth2AuthorizationController
{
    /**
     * @var AuthenticationService
     */
    private $authenticationService;

    /**
     * @var AuthorizationServer
     */
    private $authorizationServer;

    /**
     * @var ConfigurationService
     */
    private $configurationService;

    /**
     * @param AuthenticationService $authenticationService
     * @param AuthorizationServer $authorizationServer
     * @param ConfigurationService $configurationService
     */
    public function __construct(
        AuthenticationService $authenticationService,
        AuthorizationServer $authorizationServer,
        ConfigurationService $configurationService
    ) {
        $this->authenticationService = $authenticationService;
        $this->authorizationServer = $authorizationServer;
        $this->configurationService = $configurationService;
    }

    public function __invoke(ServerRequest $request): \Psr\Http\Message\ResponseInterface
    {
        $authorizationRequest = $this->authorizationServer->validateAuthorizationRequest($request);

        $user = $this->authenticationService->getAuthenticateUser($request);

        $authorizationRequest->setUser($user);
        $authorizationRequest->setAuthorizationApproved(true);

        // TODO mivanci acr-values
        // * check for acr_values request parameter and make it available in authZ request
        // * consider saving acr_values parameter for authZ request in DB
        // * check if required acr value is essential or voluntary, and depending on authN performed return appropriate
        // acr claim in ID token, or error out if required ACR is not possible

        if ($authorizationRequest instanceof AuthorizationRequest) {
            $authorizationRequest->setIsCookieBasedAuthn($this->authenticationService->isCookieBasedAuthn());
            $authorizationRequest->setAuthSourceId($this->authenticationService->getAuthSourceId());

            $this->validatePostAuthnAuthorizationRequest($authorizationRequest);
        }

        return $this->authorizationServer->completeAuthorizationRequest($authorizationRequest, new Response());
    }

    /**
     * Validate authorization request after the authn has been performed. For example, check if the
     * ACR claim has been requested and that authn performed satisfies it.
     * @param AuthorizationRequest $authorizationRequest
     * @throws \Exception
     */
    protected function validatePostAuthnAuthorizationRequest(AuthorizationRequest &$authorizationRequest)
    {
        $this->validateAcr($authorizationRequest);
    }

    /**
     * @param AuthorizationRequest $authorizationRequest
     * @throws \Exception
     */
    protected function validateAcr(AuthorizationRequest &$authorizationRequest): void
    {
        // If no ACRs requested, don't do anything.
        if (($requestedAcrValues = $authorizationRequest->getRequestedAcrValues()) === null) {
            return;
        }

        if (($authSourceId = $authorizationRequest->getAuthSourceId()) === null) {
            throw OidcServerException::serverError('authSourceId not set on authz request');
        }
        if (($isCookieBasedAuthn = $authorizationRequest->getIsCookieBasedAuthn()) === null) {
            throw OidcServerException::serverError('isCookieBasedAuthn not set on authz request');
        }

        $availableAuthSourceAcrs = $this->configurationService->getAuthSourcesToAcrValuesMap()[$authSourceId] ?? [];
        $forcedAcrForCookieAuthentication = $this->configurationService->getForcedAcrValueForCookieAuthentication();

        if ($forcedAcrForCookieAuthentication !== null && $isCookieBasedAuthn) {
            $availableAuthSourceAcrs = [$forcedAcrForCookieAuthentication];
        }

        $isAcrEssential = $requestedAcrValues['essential'] ?? false;

        $matchedAcrs = array_intersect($availableAuthSourceAcrs, $requestedAcrValues);

        if (!empty($matchedAcrs)) {
            $authorizationRequest->setAcr(current($matchedAcrs));
            return;
        }

        if ($isAcrEssential) {
            throw OidcServerException::accessDenied('could not satisfy requested ACR');
        }

        // If the ACR is not essential, we should return current session ACR (if we have one available)...
        if (! empty($availableAuthSourceAcrs)) {
            $authorizationRequest->setAcr(current($availableAuthSourceAcrs));
        }

        // ...according to spec we have to return acr claim, and we don't have one available...
        $authorizationRequest->setAcr('N/A');
    }
}

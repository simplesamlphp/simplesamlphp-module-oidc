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
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;

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
     * @param AuthenticationService $authenticationService
     * @param AuthorizationServer $authorizationServer
     */
    public function __construct(
        AuthenticationService $authenticationService,
        AuthorizationServer $authorizationServer
    ) {
        $this->authenticationService = $authenticationService;
        $this->authorizationServer = $authorizationServer;
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
        }

        return $this->authorizationServer->completeAuthorizationRequest($authorizationRequest, new Response());
    }
}

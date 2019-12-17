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

namespace SimpleSAML\Modules\OpenIDConnect\Controller;

use League\OAuth2\Server\AuthorizationServer;
use SimpleSAML\Modules\OpenIDConnect\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\AuthenticationService;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class OAuth2AuthorizationController
{
    use GetClientFromRequestTrait;

    /**
     * @var AuthenticationService
     */
    private $authenticationService;

    /**
     * @var AuthorizationServer
     */
    private $authorizationServer;


    /**
     * @param \SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository $clientRespository
     * @param \SimpleSAML\Modules\OpenIDConnect\Services\AuthenticationService $authenticationService
     * @param \League\OAuth2\Server\AuthorizationServer $authorizationServer
     */
    public function __construct(
        ClientRepository $clientRepository,
        AuthenticationService $authenticationService,
        AuthorizationServer $authorizationServer
    ) {
        $this->clientRepository = $clientRepository;
        $this->authenticationService = $authenticationService;
        $this->authorizationServer = $authorizationServer;
    }


    /**
     * @param \Zend\Diactoros\ServerRequest $request
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke(ServerRequest $request)
    {
        $authSource = $this->getClientFromRequest($request)->getAuthSource();
        $user = $this->authenticationService->getAuthenticateUser($authSource);

        $authorizationRequest = $this->authorizationServer->validateAuthorizationRequest($request);
        $authorizationRequest->setUser($user);
        $authorizationRequest->setAuthorizationApproved(true);

        return $this->authorizationServer->completeAuthorizationRequest($authorizationRequest, new Response());
    }
}

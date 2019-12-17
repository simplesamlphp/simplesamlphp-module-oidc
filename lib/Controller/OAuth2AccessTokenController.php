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
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class OAuth2AccessTokenController
{
    /**
     * @var AuthorizationServer
     */
    private $authorizationServer;


    /**
     * @param \League\OAuth2\Server\AuthorizationServer $authorizationServer
     */
    public function __construct(AuthorizationServer $authorizationServer)
    {
        $this->authorizationServer = $authorizationServer;
    }


    /**
     * @param \Zend\Diactoros\ServerRequest $request
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke(ServerRequest $request)
    {
        return $this->authorizationServer->respondToAccessTokenRequest($request, new Response());
    }
}

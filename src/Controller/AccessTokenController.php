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
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;

class AccessTokenController
{
    public function __construct(private readonly AuthorizationServer $authorizationServer)
    {
    }

    /**
     * @throws OAuthServerException
     */
    public function __invoke(ServerRequest $request): ResponseInterface
    {
        return $this->authorizationServer->respondToAccessTokenRequest($request, new Response());
    }
}

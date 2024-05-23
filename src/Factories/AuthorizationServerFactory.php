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
namespace SimpleSAML\Module\oidc\Factories;

use DateInterval;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Server\Grants\OAuth2ImplicitGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\ScopeRepository;
use SimpleSAML\Module\oidc\Server\ResponseTypes\IdTokenResponse;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;

class AuthorizationServerFactory
{
    public function __construct(
        private readonly ClientRepository $clientRepository,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly ScopeRepository $scopeRepository,
        private readonly AuthCodeGrant $authCodeGrant,
        private readonly OAuth2ImplicitGrant $oAuth2ImplicitGrant,
        private readonly ImplicitGrant $implicitGrant,
        private readonly RefreshTokenGrant $refreshTokenGrant,
        private readonly DateInterval $accessTokenDuration,
        private readonly IdTokenResponse $idTokenResponse,
        private readonly RequestRulesManager $requestRulesManager,
        private readonly CryptKey $privateKey,
        private readonly string $encryptionKey,
    ) {
    }

    public function build(): AuthorizationServer
    {
        $authorizationServer = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $this->privateKey,
            $this->encryptionKey,
            $this->idTokenResponse,
            $this->requestRulesManager,
        );

        $authorizationServer->enableGrantType(
            $this->authCodeGrant,
            $this->accessTokenDuration,
        );

        $authorizationServer->enableGrantType(
            $this->oAuth2ImplicitGrant,
            $this->accessTokenDuration,
        );

        $authorizationServer->enableGrantType(
            $this->implicitGrant,
            $this->accessTokenDuration,
        );

        $authorizationServer->enableGrantType(
            $this->refreshTokenGrant,
            $this->accessTokenDuration,
        );

        return $authorizationServer;
    }
}

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

use League\OAuth2\Server\CryptKey;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\ScopeRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Server\Grants\PreAuthCodeGrant;
use SimpleSAML\Module\oidc\Server\Grants\RefreshTokenGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\ResponseTypes\IdTokenResponse;

class AuthorizationServerFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly ClientRepository $clientRepository,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly ScopeRepository $scopeRepository,
        private readonly AuthCodeGrant $authCodeGrant,
        private readonly ImplicitGrant $implicitGrant,
        private readonly RefreshTokenGrant $refreshTokenGrant,
        private readonly IdTokenResponse $idTokenResponse,
        private readonly RequestRulesManager $requestRulesManager,
        private readonly CryptKey $privateKey,
        private readonly PreAuthCodeGrant $preAuthCodeGrant,
    ) {
    }

    public function build(): AuthorizationServer
    {
        $authorizationServer = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $this->privateKey,
            $this->moduleConfig->getEncryptionKey(),
            $this->idTokenResponse,
            $this->requestRulesManager,
        );

        $authorizationServer->enableGrantType(
            $this->authCodeGrant,
            $this->moduleConfig->getAccessTokenDuration(),
        );

        $authorizationServer->enableGrantType(
            $this->implicitGrant,
            $this->moduleConfig->getAccessTokenDuration(),
        );

        $authorizationServer->enableGrantType(
            $this->refreshTokenGrant,
            $this->moduleConfig->getAccessTokenDuration(),
        );

        // TODO mivanci Only enable if VCI is enabled.
        $authorizationServer->enableGrantType(
            $this->preAuthCodeGrant,
            $this->moduleConfig->getAccessTokenDuration(),
        );

        return $authorizationServer;
    }
}

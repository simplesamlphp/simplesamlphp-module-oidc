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

namespace SimpleSAML\Module\oidc\Factories;

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
    /**
     * @var ClientRepository
     */
    private $clientRepository;

    /**
     * @var AccessTokenRepository
     */
    private $accessTokenRepository;

    /**
     * @var ScopeRepository
     */
    private $scopeRepository;

    /**
     * @var AuthCodeGrant
     */
    private $authCodeGrant;

    /**
     * @var OAuth2ImplicitGrant
     */
    private $oAuth2ImplicitGrant;

    /**
     * @var RefreshTokenGrant
     */
    private $refreshTokenGrant;

    /**
     * @var \DateInterval
     */
    private $accessTokenDuration;

    /**
     * @var string
     */
    private $encryptionKey;

    /**
     * @var IdTokenResponse
     */
    private $idTokenResponse;

    /**
     * @var RequestRulesManager
     */
    protected $requestRulesManager;
    /**
     * @var ImplicitGrant
     */
    private $implicitGrant;
    /**
     * @var CryptKey
     */
    private $privateKey;

    /**
     * @param ClientRepository $clientRepository
     * @param AccessTokenRepository $accessTokenRepository
     * @param ScopeRepository $scopeRepository
     * @param AuthCodeGrant $authCodeGrant
     * @param OAuth2ImplicitGrant $oAuth2ImplicitGrant
     * @param ImplicitGrant $implicitGrant
     * @param RefreshTokenGrant $refreshTokenGrant
     * @param \DateInterval $accessTokenDuration
     * @param IdTokenResponse $idTokenResponse
     * @param RequestRulesManager $requestRulesManager
     * @param CryptKey $privateKey
     * @param string $encryptionKey
     */
    public function __construct(
        ClientRepository $clientRepository,
        AccessTokenRepository $accessTokenRepository,
        ScopeRepository $scopeRepository,
        AuthCodeGrant $authCodeGrant,
        OAuth2ImplicitGrant $oAuth2ImplicitGrant,
        ImplicitGrant $implicitGrant,
        RefreshTokenGrant $refreshTokenGrant,
        \DateInterval $accessTokenDuration,
        IdTokenResponse $idTokenResponse,
        RequestRulesManager $requestRulesManager,
        CryptKey $privateKey,
        string $encryptionKey
    ) {
        $this->clientRepository = $clientRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->scopeRepository = $scopeRepository;
        $this->authCodeGrant = $authCodeGrant;
        $this->oAuth2ImplicitGrant = $oAuth2ImplicitGrant;
        $this->implicitGrant = $implicitGrant;
        $this->refreshTokenGrant = $refreshTokenGrant;
        $this->accessTokenDuration = $accessTokenDuration;
        $this->idTokenResponse = $idTokenResponse;
        $this->requestRulesManager = $requestRulesManager;
        $this->privateKey = $privateKey;
        $this->encryptionKey = $encryptionKey;
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
            $this->requestRulesManager
        );

        $authorizationServer->enableGrantType(
            $this->authCodeGrant,
            $this->accessTokenDuration
        );

        $authorizationServer->enableGrantType(
            $this->oAuth2ImplicitGrant,
            $this->accessTokenDuration
        );

        $authorizationServer->enableGrantType(
            $this->implicitGrant,
            $this->accessTokenDuration
        );

        $authorizationServer->enableGrantType(
            $this->refreshTokenGrant,
            $this->accessTokenDuration
        );

        return $authorizationServer;
    }
}

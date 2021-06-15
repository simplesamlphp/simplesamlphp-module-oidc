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

namespace SimpleSAML\Modules\OpenIDConnect\Factories;

use SimpleSAML\Modules\OpenIDConnect\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\AuthCodeGrant;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\OAuth2ImplicitGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ScopeRepository;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\RequestRulesManager;
use SimpleSAML\Utils\Config;

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
     * @var IdTokenResponseFactory
     */
    private $idTokenResponseFactory;

    /**
     * @var RequestRulesManager
     */
    protected $requestRulesManager;
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
     * @param RefreshTokenGrant $refreshTokenGrant
     * @param \DateInterval $accessTokenDuration
     * @param IdTokenResponseFactory $idTokenResponseFactory
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
        RefreshTokenGrant $refreshTokenGrant,
        \DateInterval $accessTokenDuration,
        IdTokenResponseFactory $idTokenResponseFactory,
        RequestRulesManager $requestRulesManager,
        CryptKey $privateKey,
        string $encryptionKey
    ) {
        $this->clientRepository = $clientRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->scopeRepository = $scopeRepository;
        $this->authCodeGrant = $authCodeGrant;
        $this->oAuth2ImplicitGrant = $oAuth2ImplicitGrant;
        $this->refreshTokenGrant = $refreshTokenGrant;
        $this->accessTokenDuration = $accessTokenDuration;
        $this->idTokenResponseFactory = $idTokenResponseFactory;
        $this->requestRulesManager = $requestRulesManager;
        $this->privateKey = $privateKey;
        $this->encryptionKey = $encryptionKey;
    }

    public function build(): AuthorizationServer
    {
        $privateKeyPath = Config::getCertPath('oidc_module.pem');
        $encryptionKey = Config::getSecretSalt();
        $idTokenResponse = $this->idTokenResponseFactory->build();

        $authorizationServer = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $this->privateKey,
            $this->encryptionKey,
            $idTokenResponse,
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
            $this->refreshTokenGrant,
            $this->accessTokenDuration
        );

        return $authorizationServer;
    }
}

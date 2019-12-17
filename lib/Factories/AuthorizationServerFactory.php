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

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ScopeRepository;
use SimpleSAML\Utils\Config;

class AuthorizationServerFactory
{
    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository
     */
    private $clientRepository;

    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository
     */
    private $accessTokenRepository;

    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Repositories\ScopeRepository
     */
    private $scopeRepository;

    /**
     * @var \League\OAuth2\Server\Grant\AuthCodeGrant
     */
    private $authCodeGrant;

    /**
     * @var \League\OAuth2\Server\Grant\ImplicitGrant
     */
    private $implicitGrant;

    /**
     * @var \League\OAuth2\Server\Grant\RefreshTokenGrant
     */
    private $refreshTokenGrant;

    /**
     * @var \DateInterval
     */
    private $accessTokenDuration;

    /**
     * @var string|null
     */
    private $passPhrase;

    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Factories\IdTokenResponseFactory
     */
    private $idTokenResponseFactory;


    /**
     * @param \SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository $clientRepository
     * @param \SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository $accessTokenRepository
     * @param \SimpleSAML\Modules\OpenIDConnect\Repositories\ScopeRepository $scopeRepository
     * @param \League\OAuth2\Server\Grant\AuthCodeGrant $authCodeGrant
     * @param \League\OAuth2\Server\Grant\ImplicitGrant $implicitGrant
     * @param \League\OAuth2\Server\Grant\RefreshTokenGrant $refreshTokenGrant
     * @param \DateInterval $accessTokenDuration
     * @param \SimpleSAML\Modules\OpenIDConnect\Factories\IdTokenResponseFactory $idTokenResponseFactory
     * @param string|null $passPhrase
     */ 
    public function __construct(
        ClientRepository $clientRepository,
        AccessTokenRepository $accessTokenRepository,
        ScopeRepository $scopeRepository,
        AuthCodeGrant $authCodeGrant,
        ImplicitGrant $implicitGrant,
        RefreshTokenGrant $refreshTokenGrant,
        \DateInterval $accessTokenDuration,
        IdTokenResponseFactory $idTokenResponseFactory,
        string $passPhrase = null
    ) {
        $this->clientRepository = $clientRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->scopeRepository = $scopeRepository;
        $this->authCodeGrant = $authCodeGrant;
        $this->implicitGrant = $implicitGrant;
        $this->refreshTokenGrant = $refreshTokenGrant;
        $this->accessTokenDuration = $accessTokenDuration;
        $this->idTokenResponseFactory = $idTokenResponseFactory;
        $this->passPhrase = $passPhrase;
    }


    /**
     * @return \League\OAuth2\Server\AuthorizationServer
     */
    public function build()
    {
        $privateKeyPath = Config::getCertPath('oidc_module.pem');
        $encryptionKey = Config::getSecretSalt();
        $idTokenResponse = $this->idTokenResponseFactory->build();

        $authorizationServer = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            new CryptKey($privateKeyPath, $this->passPhrase),
            $encryptionKey,
            $idTokenResponse
        );

        $authorizationServer->enableGrantType(
            $this->authCodeGrant,
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

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
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;
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
     * @var UserRepository
     */
    private $userRepository;
    /**
     * @var AuthCodeGrant
     */
    private $authCodeGrant;
    /**
     * @var ImplicitGrant
     */
    private $implicitGrant;
    /**
     * @var RefreshTokenGrant
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
     * @var IdTokenResponseFactory
     */
    private $idTokenResponseFactory;

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

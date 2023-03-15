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

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResourceServer;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;

class ResourceServerFactory
{
    private AccessTokenRepositoryInterface $accessTokenRepository;

    /**
     * @var CryptKey
     */
    private $publicKey;

    /**
     * @var AuthorizationValidatorInterface
     */
    private $authorizationValidator;

    public function __construct(
        AccessTokenRepositoryInterface $accessTokenRepository,
        CryptKey $publicKey,
        AuthorizationValidatorInterface $authorizationValidator
    ) {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->publicKey = $publicKey;
        $this->authorizationValidator = $authorizationValidator;
    }

    public function build(): ResourceServer
    {
        return new ResourceServer(
            $this->accessTokenRepository,
            $this->publicKey,
            $this->authorizationValidator
        );
    }
}

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

use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResourceServer;
use SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository;
use SimpleSAML\Utils\Config;

class ResourceServerFactory
{
    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository
     */
    private $accessTokenRepository;


    /**
     * @param \SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository $accessTokenRepository
     */
    public function __construct(AccessTokenRepository $accessTokenRepository)
    {
        $this->accessTokenRepository = $accessTokenRepository;
    }


    /**
     * @return \League\OAuth2\Server\ResourceServer
     */
    public function build()
    {
        $publicKeyPath = Config::getCertPath('oidc_module.crt');

        return new ResourceServer(
            $this->accessTokenRepository,
            new CryptKey($publicKeyPath)
        );
    }
}

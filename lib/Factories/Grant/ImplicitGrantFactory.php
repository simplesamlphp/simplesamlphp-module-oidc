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

namespace SimpleSAML\Modules\OpenIDConnect\Factories\Grant;

use League\OAuth2\Server\Grant\ImplicitGrant;

class ImplicitGrantFactory
{
    /**
     * @var \DateInterval
     */
    private $accessTokenDuration;


    /**
     * @param \DateInterval $accessTokenDuration
     */
    public function __construct(\DateInterval $accessTokenDuration)
    {
        $this->accessTokenDuration = $accessTokenDuration;
    }


    /**
     * @return \League\OAuth2\Server\Grant\ImplicitGrant
     */
    public function build()
    {
        return new ImplicitGrant($this->accessTokenDuration);
    }
}

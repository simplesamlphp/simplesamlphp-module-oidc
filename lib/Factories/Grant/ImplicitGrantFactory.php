<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
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

    public function __construct(\DateInterval $accessTokenDuration)
    {
        $this->accessTokenDuration = $accessTokenDuration;
    }

    public function build()
    {
        return new ImplicitGrant($this->accessTokenDuration);
    }
}

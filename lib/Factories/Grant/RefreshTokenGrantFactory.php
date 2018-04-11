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

use League\OAuth2\Server\Grant\RefreshTokenGrant;
use SimpleSAML\Modules\OpenIDConnect\Repositories\RefreshTokenRepository;

class RefreshTokenGrantFactory
{
    /**
     * @var RefreshTokenRepository
     */
    private $refreshTokenRepository;
    /**
     * @var \DateInterval
     */
    private $refreshTokenDuration;

    public function __construct(
        RefreshTokenRepository $refreshTokenRepository,
        \DateInterval $refreshTokenDuration
    ) {
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->refreshTokenDuration = $refreshTokenDuration;
    }

    public function build()
    {
        $refreshTokenGrant = new RefreshTokenGrant($this->refreshTokenRepository);
        $refreshTokenGrant->setRefreshTokenTTL($this->refreshTokenDuration);

        return $refreshTokenGrant;
    }
}

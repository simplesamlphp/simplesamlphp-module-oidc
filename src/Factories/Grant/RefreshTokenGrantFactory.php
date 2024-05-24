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
namespace SimpleSAML\Module\oidc\Factories\Grant;

use DateInterval;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Server\Grants\RefreshTokenGrant;

class RefreshTokenGrantFactory
{
    public function __construct(
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly DateInterval $refreshTokenDuration,
    ) {
    }

    public function build(): RefreshTokenGrant
    {
        $refreshTokenGrant = new RefreshTokenGrant($this->refreshTokenRepository);
        $refreshTokenGrant->setRefreshTokenTTL($this->refreshTokenDuration);

        return $refreshTokenGrant;
    }
}

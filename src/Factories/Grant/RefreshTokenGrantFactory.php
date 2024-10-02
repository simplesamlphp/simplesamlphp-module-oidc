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

use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Server\Grants\RefreshTokenGrant;

class RefreshTokenGrantFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly AccessTokenEntityFactory $accessTokenEntityFactory,
    ) {
    }

    public function build(): RefreshTokenGrant
    {
        $refreshTokenGrant = new RefreshTokenGrant($this->refreshTokenRepository, $this->accessTokenEntityFactory);
        $refreshTokenGrant->setRefreshTokenTTL($this->moduleConfig->getRefreshTokenDuration());

        return $refreshTokenGrant;
    }
}

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
use SimpleSAML\Module\oidc\Server\Grants\OAuth2ImplicitGrant;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;

class OAuth2ImplicitGrantFactory
{
    public function __construct(
        private readonly DateInterval $accessTokenDuration,
        private readonly RequestRulesManager $requestRulesManager,
    ) {
    }

    public function build(): OAuth2ImplicitGrant
    {
        return new OAuth2ImplicitGrant($this->accessTokenDuration, '#', $this->requestRulesManager);
    }
}

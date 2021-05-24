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

use SimpleSAML\Modules\OpenIDConnect\Server\Grants\OAuth2ImplicitGrant;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\RequestRulesManager;

class OAuth2ImplicitGrantFactory
{
    /**
     * @var \DateInterval
     */
    private $accessTokenDuration;

    /**
     * @var RequestRulesManager
     */
    protected $requestRulesManager;

    public function __construct(\DateInterval $accessTokenDuration, RequestRulesManager $requestRulesManager)
    {
        $this->accessTokenDuration = $accessTokenDuration;
        $this->requestRulesManager = $requestRulesManager;
    }

    public function build(): OAuth2ImplicitGrant
    {
        return new OAuth2ImplicitGrant($this->accessTokenDuration, '#', $this->requestRulesManager);
    }
}

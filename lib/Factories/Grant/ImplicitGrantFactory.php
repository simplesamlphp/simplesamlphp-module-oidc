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

namespace SimpleSAML\Module\oidc\Factories\Grant;

use DateInterval;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;

class ImplicitGrantFactory
{
    /**
     * @var IdTokenBuilder
     */
    private $idTokenBuilder;

    /**
     * @var DateInterval
     */
    private $accessTokenDuration;

    /**
     * @var RequestRulesManager
     */
    protected $requestRulesManager;

    public function __construct(
        IdTokenBuilder $idTokenBuilder,
        DateInterval $accessTokenDuration,
        RequestRulesManager $requestRulesManager
    ) {
        $this->idTokenBuilder = $idTokenBuilder;
        $this->accessTokenDuration = $accessTokenDuration;
        $this->requestRulesManager = $requestRulesManager;
    }

    public function build(): ImplicitGrant
    {
        return new ImplicitGrant(
            $this->idTokenBuilder,
            $this->accessTokenDuration,
            '#',
            $this->requestRulesManager
        );
    }
}

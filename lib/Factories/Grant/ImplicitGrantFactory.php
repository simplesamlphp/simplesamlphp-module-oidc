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

use DateInterval;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\ImplicitGrant;
use SimpleSAML\Modules\OpenIDConnect\Services\IdTokenBuilder;
use SimpleSAML\Modules\OpenIDConnect\Services\RequestedClaimsEncoderService;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\RequestRulesManager;

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

    /**
     * @var RequestedClaimsEncoderService
     */
    private $requestedClaimsEncoderService;

    public function __construct(
        IdTokenBuilder $idTokenBuilder,
        DateInterval $accessTokenDuration,
        RequestRulesManager $requestRulesManager,
        RequestedClaimsEncoderService $requestedClaimsEncoderService
    ) {
        $this->idTokenBuilder = $idTokenBuilder;
        $this->accessTokenDuration = $accessTokenDuration;
        $this->requestRulesManager = $requestRulesManager;
        $this->requestedClaimsEncoderService = $requestedClaimsEncoderService;
    }

    public function build(): ImplicitGrant
    {
        return new ImplicitGrant(
            $this->idTokenBuilder,
            $this->accessTokenDuration,
            '#',
            $this->requestRulesManager,
            $this->requestedClaimsEncoderService
        );
    }
}

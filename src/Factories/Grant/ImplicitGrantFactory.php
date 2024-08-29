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

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

class ImplicitGrantFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly IdTokenBuilder $idTokenBuilder,
        private readonly RequestRulesManager $requestRulesManager,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly RequestParamsResolver $requestParamsResolver,
    ) {
    }

    public function build(): ImplicitGrant
    {
        return new ImplicitGrant(
            $this->idTokenBuilder,
            $this->moduleConfig->getAccessTokenDuration(),
            $this->accessTokenRepository,
            $this->requestRulesManager,
            $this->requestParamsResolver,
            '#',
        );
    }
}

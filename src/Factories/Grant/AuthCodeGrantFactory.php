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

use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;

class AuthCodeGrantFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly AuthCodeRepository $authCodeRepository,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly RequestRulesManager $requestRulesManager,
        private readonly Helpers $helpers,
    ) {
    }

    /**
     * @throws \Exception
     */
    public function build(): AuthCodeGrant
    {
        $authCodeGrant = new AuthCodeGrant(
            $this->authCodeRepository,
            $this->accessTokenRepository,
            $this->refreshTokenRepository,
            $this->moduleConfig->getAuthCodeDuration(),
            $this->requestRulesManager,
            $this->helpers,
        );
        $authCodeGrant->setRefreshTokenTTL($this->moduleConfig->getRefreshTokenDuration());

        return $authCodeGrant;
    }
}

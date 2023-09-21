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
use Exception;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;

class AuthCodeGrantFactory
{
    public function __construct(
        private AuthCodeRepository $authCodeRepository,
        private AccessTokenRepository $accessTokenRepository,
        private RefreshTokenRepository $refreshTokenRepository,
        private DateInterval $refreshTokenDuration,
        private DateInterval $authCodeDuration,
        private RequestRulesManager $requestRulesManager
    ) {
    }

    /**
     * @throws Exception
     */
    public function build(): AuthCodeGrant
    {
        $authCodeGrant = new AuthCodeGrant(
            $this->authCodeRepository,
            $this->accessTokenRepository,
            $this->refreshTokenRepository,
            $this->authCodeDuration,
            $this->requestRulesManager
        );
        $authCodeGrant->setRefreshTokenTTL($this->refreshTokenDuration);

        return $authCodeGrant;
    }
}

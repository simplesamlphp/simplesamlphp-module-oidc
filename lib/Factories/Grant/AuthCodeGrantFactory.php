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

use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;

class AuthCodeGrantFactory
{
    /**
     * @var \SimpleSAML\Module\oidc\Repositories\AuthCodeRepository
     */
    private $authCodeRepository;

    private AccessTokenRepositoryInterface $accessTokenRepository;

    /**
     * @var \SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository
     */
    private $refreshTokenRepository;

    /**
     * @var \DateInterval
     */
    private $refreshTokenDuration;

    /**
     * @var \DateInterval
     */
    private $authCodeDuration;
    /**
     * @var RequestRulesManager
     */
    private $requestRulesManager;

    private ConfigurationService $configurationService;

    public function __construct(
        AuthCodeRepository $authCodeRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        RefreshTokenRepository $refreshTokenRepository,
        \DateInterval $refreshTokenDuration,
        \DateInterval $authCodeDuration,
        RequestRulesManager $requestRulesManager,
        ConfigurationService $configurationService
    ) {
        $this->authCodeRepository = $authCodeRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->refreshTokenRepository = $refreshTokenRepository;
        $this->refreshTokenDuration = $refreshTokenDuration;
        $this->authCodeDuration = $authCodeDuration;
        $this->requestRulesManager = $requestRulesManager;
        $this->configurationService = $configurationService;
    }

    public function build(): AuthCodeGrant
    {
        $authCodeGrant = new AuthCodeGrant(
            $this->authCodeRepository,
            $this->accessTokenRepository,
            $this->refreshTokenRepository,
            $this->authCodeDuration,
            $this->requestRulesManager,
            $this->configurationService
        );
        $authCodeGrant->setRefreshTokenTTL($this->refreshTokenDuration);

        return $authCodeGrant;
    }
}

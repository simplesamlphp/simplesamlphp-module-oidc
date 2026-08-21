<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Grant;

use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Server\Grants\RefreshTokenGrant;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;

class RefreshTokenGrantFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly AccessTokenEntityFactory $accessTokenEntityFactory,
        private readonly RefreshTokenIssuer $refreshTokenIssuer,
        private readonly AuthenticatedOAuth2ClientResolver $authenticatedOAuth2ClientResolver,
        private readonly LoggerService $loggerService,
    ) {
    }

    public function build(): RefreshTokenGrant
    {
        $refreshTokenGrant = new RefreshTokenGrant(
            $this->refreshTokenRepository,
            $this->accessTokenEntityFactory,
            $this->refreshTokenIssuer,
            $this->authenticatedOAuth2ClientResolver,
            $this->loggerService,
        );

        $refreshTokenGrant->setRefreshTokenTTL($this->moduleConfig->getRefreshTokenDuration());

        return $refreshTokenGrant;
    }
}

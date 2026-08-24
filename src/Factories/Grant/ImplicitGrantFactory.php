<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Grant;

use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

class ImplicitGrantFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly IdTokenBuilder $idTokenBuilder,
        private readonly RequestRulesManager $requestRulesManager,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly RequestParamsResolver $requestParamsResolver,
        private readonly AccessTokenEntityFactory $accessTokenEntityFactory,
        private readonly LoggerService $loggerService,
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
            $this->accessTokenEntityFactory,
            $this->loggerService,
        );
    }
}

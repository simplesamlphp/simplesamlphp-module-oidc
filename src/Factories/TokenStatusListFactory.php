<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\TokenStatusList;

class TokenStatusListFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * @throws \ReflectionException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function build(): TokenStatusList
    {
        return new TokenStatusList(
            supportedAlgorithms: $this->moduleConfig->getSupportedAlgorithms(),
            timestampValidationLeeway: $this->moduleConfig->getTimestampValidationLeeway(),
            logger: $this->loggerService,
        );
    }
}

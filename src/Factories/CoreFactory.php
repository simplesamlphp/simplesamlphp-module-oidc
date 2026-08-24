<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Core;

class CoreFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * Builds a new Core instance.
     *
     * @return \SimpleSAML\OpenID\Core
     */
    public function build(): Core
    {
        return new Core(
            supportedAlgorithms: $this->moduleConfig->getSupportedAlgorithms(),
            timestampValidationLeeway: $this->moduleConfig->getTimestampValidationLeeway(),
            logger: $this->loggerService,
        );
    }
}

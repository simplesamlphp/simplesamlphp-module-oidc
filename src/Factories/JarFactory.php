<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Jar;

class JarFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * Builds a new Jar instance.
     *
     * @return Jar
     */
    public function build(): Jar
    {
        return new Jar(
            supportedAlgorithms: $this->moduleConfig->getSupportedAlgorithms(),
            timestampValidationLeeway: $this->moduleConfig->getTimestampValidationLeeway(),
        );
    }
}

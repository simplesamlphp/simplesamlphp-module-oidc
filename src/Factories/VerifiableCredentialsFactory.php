<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\VerifiableCredentials;

class VerifiableCredentialsFactory
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
    public function build(): VerifiableCredentials
    {
        return new VerifiableCredentials(
            supportedAlgorithms: $this->moduleConfig->getSupportedAlgorithms(),
            logger: $this->loggerService,
        );
    }
}

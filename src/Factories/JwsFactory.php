<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Jws;

class JwsFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
    ) {
    }

    public function build(): Jws
    {
        return new Jws(
            supportedAlgorithms: $this->moduleConfig->getSupportedAlgorithms(),
            supportedSerializers: $this->moduleConfig->getSupportedSerializers(),
            timestampValidationLeeway: $this->moduleConfig->getTimestampValidationLeeway(),
            logger: $this->loggerService,
        );
    }
}

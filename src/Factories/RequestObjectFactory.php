<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\RequestObject;

class RequestObjectFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * Builds a new RequestObject instance.
     *
     * @return RequestObject
     */
    public function build(): RequestObject
    {
        return new RequestObject(
            supportedAlgorithms: $this->moduleConfig->getSupportedAlgorithms(),
            timestampValidationLeeway: $this->moduleConfig->getTimestampValidationLeeway(),
            logger: $this->loggerService,
            httpClientConfig: $this->moduleConfig->getProtocolHttpClientOptions(),
        );
    }
}

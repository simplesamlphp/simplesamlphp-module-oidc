<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\OAuth2;

class OAuth2Factory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
    ) {
    }


    /**
     * Builds a new OAuth2 instance, the library's entry point for the JWT access token profile (RFC 9068).
     * Same algorithms, serializers and leeway as the Jws service, so a token minted through one parses
     * through the other.
     */
    public function build(): OAuth2
    {
        return new OAuth2(
            supportedSerializers: $this->moduleConfig->getSupportedSerializers(),
            supportedAlgorithms: $this->moduleConfig->getSupportedAlgorithms(),
            timestampValidationLeeway: $this->moduleConfig->getTimestampValidationLeeway(),
        );
    }
}

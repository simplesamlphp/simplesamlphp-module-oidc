<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\OpenID\Federation;

class FederationFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
        protected readonly ?FederationCache $federationCache = null,
    ) {
    }

    /**
     * @throws \ReflectionException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function build(): Federation
    {
        return new Federation(
            supportedAlgorithms: $this->moduleConfig->getSupportedAlgorithms(),
            maxCacheDuration: $this->moduleConfig->getFederationCacheMaxDurationForFetched(),
            timestampValidationLeeway: $this->moduleConfig->getTimestampValidationLeeway(),
            maxTrustChainDepth: $this->moduleConfig->getFederationMaxTrustChainDepth(),
            cache: $this->federationCache?->cache,
            logger: $this->loggerService,
            defaultTrustMarkStatusEndpointUsagePolicyEnum:
            $this->moduleConfig->getFederationTrustMarkStatusEndpointUsagePolicy(),
            httpClientConfig: $this->moduleConfig->getFederationHttpClientOptions(),
            maxAuthorityHints: $this->moduleConfig->getFederationMaxAuthorityHints(),
            maxTrustChainFetches: $this->moduleConfig->getFederationMaxTrustChainFetches(),
            trustChainResolveTimeout: $this->moduleConfig->getFederationTrustChainResolveTimeout(),
            maxFetchSizeBytes: $this->moduleConfig->getFederationMaxFetchSizeBytes(),
        );
    }
}

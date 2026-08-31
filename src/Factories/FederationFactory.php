<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Federation;

class FederationFactory
{
    /**
     * Note the factories rather than the policy and the cache themselves. Both are built from
     * configuration that can be malformed, and building either throws when it is. Taking a built one here
     * would make that throw happen while the container wires up anything that reaches this factory -
     * including the admin Configuration screens, which exist to report exactly such an option. Deferring
     * both to build() keeps them reachable.
     *
     * The policy was moved behind its factory first; the cache stayed behind and reintroduced the same
     * fault on its own, so a malformed federation cache adapter still took the federation screen down
     * before any row could report it. Do not inject a built collaborator here.
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
        protected readonly DestinationPolicyFactory $destinationPolicyFactory,
        protected readonly CacheFactory $cacheFactory,
    ) {
    }


    /**
     * @throws \ReflectionException
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException On a cache adapter which cannot be built.
     */
    public function build(): Federation
    {
        return new Federation(
            supportedAlgorithms: $this->moduleConfig->getSupportedAlgorithms(),
            maxCacheDuration: $this->moduleConfig->getFederationCacheMaxDurationForFetched(),
            timestampValidationLeeway: $this->moduleConfig->getTimestampValidationLeeway(),
            maxTrustChainDepth: $this->moduleConfig->getFederationMaxTrustChainDepth(),
            cache: $this->cacheFactory->forFederation()?->cache,
            logger: $this->loggerService,
            defaultTrustMarkStatusEndpointUsagePolicyEnum:
            $this->moduleConfig->getFederationTrustMarkStatusEndpointUsagePolicy(),
            httpClientConfig: $this->moduleConfig->getFederationHttpClientOptions(),
            maxAuthorityHints: $this->moduleConfig->getFederationMaxAuthorityHints(),
            maxTrustChainFetches: $this->moduleConfig->getFederationMaxTrustChainFetches(),
            trustChainResolveTimeout: $this->moduleConfig->getFederationTrustChainResolveTimeout(),
            maxFetchSizeBytes: $this->moduleConfig->getFederationMaxFetchSizeBytes(),
            destinationPolicy: $this->destinationPolicyFactory->build(),
        );
    }
}

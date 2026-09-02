<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Did\DidWebResolver;

/**
 * Builds the library entry point for Decentralized Identifier resolution.
 *
 * Everything reachable through it is driven from outside: a did:web identifier arrives in a wallet's
 * key proof and says where this deployment should send a request. That is what the destination policy
 * below is for, and why it is not the one every other outbound fetch uses.
 */
class DidFactory
{
    /**
     * Note the configuration rather than a built policy. Building one throws when the configuration is
     * malformed, and the container reaches this factory while wiring up the admin Configuration screens -
     * the screens whose whole purpose is to report exactly such an option. Deferring it to build() keeps
     * them reachable. Same reasoning as FederationFactory, which regressed on it once.
     *
     * The cache is taken as the factory which builds it rather than as a built one, for that same
     * reason: `vci_cache_adapter` names a class to instantiate with arguments, so building it reads
     * configuration and can throw. Constructing this factory therefore reads nothing at all, which is
     * what lets a caller hold one without inheriting a failure from DID settings it may never use.
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
        protected readonly ?CacheFactory $cacheFactory = null,
    ) {
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException On a cache adapter which can not be built.
     * @throws \SimpleSAML\OpenID\Exceptions\DidException
     * @throws \SimpleSAML\OpenID\Exceptions\DestinationPolicyException On configuration the library
     *         refuses when the policy is built, rather than letting an exemption that can never match
     *         pass for a working one.
     * @throws \Exception
     */
    public function build(): Did
    {
        return new Did(
            maxCacheDuration: $this->moduleConfig->getVciDidCacheMaxDuration(),
            cache: $this->cacheFactory?->forVci()?->cache,
            logger: $this->loggerService,
            // Through the library's own helper rather than assembled here: it is what refuses a pinning
            // mode DID resolution can not run under, and building a DestinationPolicy by hand would walk
            // around that refusal. The resolver behind this facade must likewise never be constructed
            // directly - its constructor takes any HTTP client, and so bypasses this policy, the pinning
            // requirement and the response size cap alike.
            destinationPolicy: DidWebResolver::buildDestinationPolicy(
                logger: $this->loggerService,
                addressPinningMode: $this->moduleConfig->getVciDidAddressPinningMode(),
                allowedHosts: $this->moduleConfig->getVciDidOutboundAllowedHosts(),
                allowedCidrs: $this->moduleConfig->getVciDidOutboundAllowedCidrs(),
            ),
        );
    }
}

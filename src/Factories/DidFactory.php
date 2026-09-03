<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Did\DidJwkResolver;
use SimpleSAML\OpenID\Did\DidWebResolver;
use SimpleSAML\OpenID\Did\Factories\DidDocumentFactory;

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
     * The facade this factory has already built, if it has.
     *
     * Building one instantiates the configured VCI cache adapter, which for a shared backend means
     * opening a connection, so the callers within a request share a facade instead of each getting one
     * of their own. The container held exactly one before any caller reached this factory directly;
     * this is what keeps that true now that they do, and it is why a caller may build lazily without
     * turning a single connection into one per collaborator.
     */
    protected ?Did $did = null;

    /**
     * A facade for the work which never leaves this host, kept apart from the one above.
     *
     * @see localDid()
     */
    protected ?Did $localDid = null;


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
     * The DID facade for this request, built on the first call and returned as it stands afterwards.
     *
     * Reading configuration is deferred to here rather than to the constructor, so this is the point at
     * which a malformed DID or cache setting becomes an error - which is the whole reason a caller with
     * no use for DID resolution can hold this factory safely. See {@see $did} for why the result is kept
     * rather than rebuilt.
     *
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
        return $this->did ??= $this->buildDid();
    }


    /**
     * Builds the DID document this deployment publishes for its own `did:web` identifier.
     *
     * Deliberately not reached through {@see build()}. Building that facade instantiates the
     * configured cache adapter and resolves the DID outbound destination settings, neither of which
     * this needs: the document is assembled from key material already on disk and nothing is fetched.
     * Going through it would mean a malformed `vci_cache_adapter`, or an outbound option which only
     * governs resolving *other people's* DIDs, stopping this document being served - and a credential
     * issued under a `did:web` identity can only be verified by resolving that document, so an
     * unrelated setting would make credentials already in wallets permanently unverifiable.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\DidException
     */
    public function didDocumentFactory(): DidDocumentFactory
    {
        return $this->localDid()->didDocumentFactory();
    }


    /**
     * Derives a `did:jwk` from a key already in hand, which is likewise a local operation.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\DidException
     */
    public function didJwkResolver(): DidJwkResolver
    {
        return $this->localDid()->didJwkResolver();
    }


    /**
     * A facade constructed from nothing but a logger, for the operations above.
     *
     * Every constructor argument the library takes is optional, so this reads no configuration at all
     * and therefore cannot fail on any of it. The resolvers hanging off it are deliberately not
     * exposed: its destination policy is the library's own default rather than this deployment's, so
     * resolving through it would ignore the configured allowlist. That is why the two accessors above
     * hand out the local factories rather than the facade itself, and why anything which resolves a
     * DID supplied from outside must go through {@see build()}.
     */
    protected function localDid(): Did
    {
        return $this->localDid ??= new Did(logger: $this->loggerService);
    }


    protected function buildDid(): Did
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

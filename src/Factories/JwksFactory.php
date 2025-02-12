<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\SupportedAlgorithms;

class JwksFactory
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
    public function build(): Jwks
    {
        $supportedAlgorithms = new SupportedAlgorithms(
            new SignatureAlgorithmBag(
                SignatureAlgorithmEnum::from($this->moduleConfig->getFederationSigner()->algorithmId()),
            ),
        );

        return new Jwks(
            supportedAlgorithms: $supportedAlgorithms,
            maxCacheDuration: $this->moduleConfig->getFederationCacheMaxDurationForFetched(),
            cache: $this->federationCache?->cache,
            logger: $this->loggerService,
        );
    }
}

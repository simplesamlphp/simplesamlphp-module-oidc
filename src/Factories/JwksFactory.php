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

readonly class JwksFactory
{
    public function __construct(
        protected ModuleConfig $moduleConfig,
        protected LoggerService $loggerService,
        protected ?FederationCache $federationCache = null,
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
                SignatureAlgorithmEnum::from(
                    $this->moduleConfig->getFederationSigner()?->algorithmId() ??
                        SignatureAlgorithmEnum::RS256->value,
                ),
            ),
        );

        return new Jwks(
            supportedAlgorithms: $supportedAlgorithms,
            maxCacheDuration: $this->moduleConfig->getFederationCacheMaxDuration(),
            cache: $this->federationCache?->instance,
            logger: $this->loggerService,
        );
    }
}

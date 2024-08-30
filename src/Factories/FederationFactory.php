<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\SupportedAlgorithms;

readonly class FederationFactory
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
    public function build(): Federation
    {
        $supportedAlgorithms = new SupportedAlgorithms(
            new SignatureAlgorithmBag(
                SignatureAlgorithmEnum::from(
                    $this->moduleConfig->getFederationSigner()?->algorithmId() ??
                        SignatureAlgorithmEnum::RS256->value,
                ),
            ),
        );

        return new Federation(
            supportedAlgorithms: $supportedAlgorithms,
            maxCacheDuration: $this->moduleConfig->getFederationCacheMaxDuration(),
            cache: $this->federationCache?->instance,
            logger: $this->loggerService,
        );
    }
}

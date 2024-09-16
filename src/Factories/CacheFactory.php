<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\OidcException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClassInstanceBuilder;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use Symfony\Component\Cache\Adapter\AdapterInterface;
use Symfony\Component\Cache\Psr16Cache;

class CacheFactory
{
    public function __construct(
        protected ModuleConfig $moduleConfig,
        protected LoggerService $loggerService,
        protected ClassInstanceBuilder $classInstanceBuilder,
    ) {
    }

    /**
     * @throws \SimpleSAML\Module\oidc\OidcException
     */
    public function forFederation(): ?FederationCache
    {
        $class = $this->moduleConfig->getFederationCacheAdapterClass();

        if (is_null($class)) {
            return null;
        }

        try {
            $instance = $this->classInstanceBuilder->build(
                $class,
                $this->moduleConfig->getFederationCacheAdapterArguments(),
            );
        } catch (\Throwable $exception) {
            $message = "Error building federation cache instance: " . $exception->getMessage();
            $this->loggerService->error($message);
            throw new OidcException($message);
        }

        if (!is_a($instance, AdapterInterface::class)) {
            $message = "Unexpected federation cache adapter class: $class. Expected type: " . AdapterInterface::class;
            $this->loggerService->error($message);
            throw new OidcException($message);
        }

        return new FederationCache(new Psr16Cache($instance));
    }
}

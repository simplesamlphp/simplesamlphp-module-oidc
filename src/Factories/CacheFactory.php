<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\OidcException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClassInstanceBuilder;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
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
    protected function buildAdapterInstance(
        string $class,
        array $args = [],
    ): AdapterInterface {
        try {
            $instance = $this->classInstanceBuilder->build($class, $args);
        } catch (\Throwable $exception) {
            $message = "Error building cache adapter instance: " . $exception->getMessage();
            $this->loggerService->error($message);
            throw new OidcException($message);
        }

        if (!is_a($instance, AdapterInterface::class)) {
            $message = "Unexpected cache adapter class: $class. Expected type: " . AdapterInterface::class;
            $this->loggerService->error($message);
            throw new OidcException($message);
        }

        return $instance;
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

        $adapter = $this->buildAdapterInstance(
            $class,
            $this->moduleConfig->getFederationCacheAdapterArguments(),
        );

        return new FederationCache(new Psr16Cache($adapter));
    }

    /**
     * @throws \SimpleSAML\Module\oidc\OidcException
     */
    public function forProtocol(): ?ProtocolCache
    {
        $class = $this->moduleConfig->getProtocolCacheAdapterClass();

        if (is_null($class)) {
            return null;
        }

        $adapter = $this->buildAdapterInstance(
            $class,
            $this->moduleConfig->getProtocolCacheAdapterArguments(),
        );

        return new ProtocolCache(new Psr16Cache($adapter));
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use Exception;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Module;
use SimpleSAML\Module\oidc\ModuleConfig;

class AuthProcService
{
    /**
     * @var ProcessingFilter[] Filters to be applied to OIDC state.
     */
    private array $filters = [];

    /**
     * AuthProcService constructor.
     *
     * @throws Exception
     * @see \SimpleSAML\Auth\ProcessingChain for original implementation
     */
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
    ) {
        $this->loadFilters();
    }

    /**
     * Load filters defined in configuration.
     * @throws Exception
     */
    private function loadFilters(): void
    {
        $oidcAuthProcFilters = $this->moduleConfig->getAuthProcFilters();
        $this->filters = $this->parseFilterList($oidcAuthProcFilters);
    }

    /**
     * Parse an array of authentication processing filters.
     * @see \SimpleSAML\Auth\ProcessingChain::parseFilterList for original implementation
     *
     * @param array $filterSrc Array with filter configuration.
     * @return array<ProcessingFilter>  Array of ProcessingFilter objects.
     * @throws Exception
     */
    private function parseFilterList(array $filterSrc): array
    {
        $parsedFilters = [];

        foreach ($filterSrc as $priority => $filterConfig) {
            if (is_string($filterConfig)) {
                $filterConfig = ['class' => $filterConfig];
            }

            if (!is_array($filterConfig)) {
                throw new Exception('Invalid authentication processing filter configuration: ' .
                                     'One of the filters wasn\'t a string or an array.');
            }

            if (!array_key_exists('class', $filterConfig)) {
                throw new Exception('Authentication processing filter without name given.');
            }

            if (!is_string($filterConfig['class'])) {
                throw new Exception('Invalid class value for authentication processing filter configuration.');
            }

            $className = Module::resolveClass(
                $filterConfig['class'],
                'Auth\Process',
                '\\' . ProcessingFilter::class,
            );

            if (!is_a($className, ProcessingFilter::class, true)) {
                throw new Exception(
                    'Authentication processing filter class configuration is not ProcessingFilter instance.',
                );
            }

            $filterConfig['%priority'] = $priority;
            unset($filterConfig['class']);

            /**
             * @psalm-suppress UnsafeInstantiation
             */
            $parsedFilters[] = new $className($filterConfig, null);
        }

        return $parsedFilters;
    }

    /**
     * Process given state array.
     */
    public function processState(array $state): array
    {
        foreach ($this->filters as $filter) {
            $filter->process($state);
        }

        return $state;
    }

    /**
     * Get filters loaded from configuration.
     *
     * @return array
     */
    public function getLoadedFilters(): array
    {
        return $this->filters;
    }
}

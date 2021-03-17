<?php

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Module;

class AuthProcService
{
    /**
     * @var ConfigurationService
     */
    private $configurationService;

    /**
     * @var array Filters to be applied to OIDC state.
     */
    private $filters = [];

    /**
     * AuthProcService constructor.
     * @param ConfigurationService $configurationService
     *
     * @throws \Exception
     * @see \SimpleSAML\Auth\ProcessingChain for original implementation
     */
    public function __construct(
        ConfigurationService $configurationService
    ) {
        $this->configurationService = $configurationService;
        $this->loadFilters();
    }

    /**
     * Load filters defined in configuration.
     * @throws \Exception
     */
    private function loadFilters(): void
    {
        $oidcAuthProcFilters = $this->configurationService->getAuthProcFilters();
        $this->filters = $this->parseFilterList($oidcAuthProcFilters);
    }

    /**
     * Parse an array of authentication processing filters.
     * @see \SimpleSAML\Auth\ProcessingChain::parseFilterList for original implementation
     *
     * @param array $filterSrc Array with filter configuration.
     * @return array  Array of ProcessingFilter objects.
     * @throws \Exception
     */
    private function parseFilterList(array $filterSrc): array
    {
        $parsedFilters = [];

        foreach ($filterSrc as $priority => $filterConfig) {
            if (is_string($filterConfig)) {
                $filterConfig = ['class' => $filterConfig];
            }

            if (!is_array($filterConfig)) {
                throw new \Exception('Invalid authentication processing filter configuration: ' .
                                     'One of the filters wasn\'t a string or an array.');
            }

            if (!array_key_exists('class', $filterConfig)) {
                throw new \Exception('Authentication processing filter without name given.');
            }

            $className = Module::resolveClass(
                $filterConfig['class'],
                'Auth\Process',
                '\SimpleSAML\Auth\ProcessingFilter'
            );

            $filterConfig['%priority'] = $priority;
            unset($filterConfig['class']);

            /**
             * @psalm-suppress InvalidStringClass
             */
            $parsedFilters[] = new $className($filterConfig, null);
        }

        return $parsedFilters;
    }

    /**
     * Process given state array.
     *
     * @param array $state
     * @return array
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

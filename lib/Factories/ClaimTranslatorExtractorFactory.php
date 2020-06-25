<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Factories;

use OpenIDConnectServer\Entities\ClaimSetEntity;
use SimpleSAML\Modules\OpenIDConnect\ClaimTranslatorExtractor;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;

class ClaimTranslatorExtractorFactory
{
    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService
     */
    private $configurationService;

    protected const CONFIG_KEY_CLAIM_NAME_PREFIX = 'claim_name_prefix';

    protected const CONFIG_KEY_MULTIPLE_CLAIM_VALUES_ALLOWED = 'are_multiple_claim_values_allowed';

    public function __construct(
        ConfigurationService $configurationService
    ) {
        $this->configurationService = $configurationService;
    }

    public function build(): ClaimTranslatorExtractor
    {
        $translatorTable = $this->configurationService->getOpenIDConnectConfiguration()->getArray('translate', []);

        $privateScopes = $this->configurationService->getOpenIDPrivateScopes();

        $claimSet = [];
        $allowedMultipleValueClaims = [];

        foreach ($privateScopes as $scopeName => $scopeConfig) {
            $claims = $scopeConfig['attributes'] ?? [];

            if ($this->isScopeClaimNamePrefixSet($scopeConfig)) {
                $prefix = $scopeConfig[self::CONFIG_KEY_CLAIM_NAME_PREFIX];

                $translatorTable = $this->applyPrefixToTranslatorTableKeys($translatorTable, $claims, $prefix);
                $claims = $this->applyPrefixToClaimNames($claims, $prefix);
            }

            $claimSet[] = new ClaimSetEntity($scopeName, $claims);

            if ($this->doesScopeAllowMultipleClaimValues($scopeConfig)) {
                $allowedMultipleValueClaims = array_merge($allowedMultipleValueClaims, $claims);
            }
        }

        return new ClaimTranslatorExtractor($claimSet, $translatorTable, $allowedMultipleValueClaims);
    }

    /**
     * Apply a prefix to translator table keys (which serve as claim names).
     *
     * @param array $translatorTable Translation table array from config
     * @param array $claims Claim names for which to apply prefix
     * @param string $prefix Prefix to apply to claim names
     * @return array Translator table with prefixed claim names
     */
    protected function applyPrefixToTranslatorTableKeys(array $translatorTable, array $claims, string $prefix): array
    {
        foreach ($claims as $claim) {
            if (array_key_exists($claim, $translatorTable)) {
                $prefixedClaimKey = $prefix . $claim;
                $translatorTable[$prefixedClaimKey] = $translatorTable[$claim];
                unset($translatorTable[$claim]);
            }
        }

        return $translatorTable;
    }

    /**
     * @param array $claims Claim names for which to apply prefix
     * @param string $prefix Prefix to apply to claim names.
     * @return array
     */
    protected function applyPrefixToClaimNames(array $claims, string $prefix): array
    {
        array_walk($claims, function (&$value, $key, $prefix) {
            $value = $prefix . $value;
        }, $prefix);

        return $claims;
    }

    /**
     * Check if the scope has a claim name prefix set
     * @param array $scopeConfig
     * @return bool
     */
    protected function isScopeClaimNamePrefixSet(array $scopeConfig): bool
    {
        return isset($scopeConfig[self::CONFIG_KEY_CLAIM_NAME_PREFIX]) &&
            is_string($scopeConfig[self::CONFIG_KEY_CLAIM_NAME_PREFIX]) &&
            !empty($scopeConfig[self::CONFIG_KEY_CLAIM_NAME_PREFIX]);
    }

    /**
     * Check if the scope allows claims to have multiple values.
     * @param array $scopeConfig
     * @return bool
     */
    protected function doesScopeAllowMultipleClaimValues(array $scopeConfig): bool
    {
        return isset($scopeConfig[self::CONFIG_KEY_MULTIPLE_CLAIM_VALUES_ALLOWED]) &&
            boolval($scopeConfig[self::CONFIG_KEY_MULTIPLE_CLAIM_VALUES_ALLOWED]);
    }
}
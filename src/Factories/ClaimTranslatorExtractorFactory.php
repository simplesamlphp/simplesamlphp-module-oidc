<?php

declare(strict_types=1);

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

namespace SimpleSAML\Module\oidc\Factories;

use Exception;
use SimpleSAML\Module\oidc\ConfigurationService;
use SimpleSAML\Module\oidc\Entity\ClaimSetEntity;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

class ClaimTranslatorExtractorFactory
{
    protected const CONFIG_KEY_CLAIM_NAME_PREFIX = 'claim_name_prefix';

    protected const CONFIG_KEY_MULTIPLE_CLAIM_VALUES_ALLOWED = 'are_multiple_claim_values_allowed';

    public function __construct(private readonly ConfigurationService $configurationService)
    {
    }

    /**
     * @throws Exception
     */
    public function build(): ClaimTranslatorExtractor
    {
        $translatorTable = $this->configurationService->getOpenIDConnectConfiguration()
            ->getOptionalArray('translate', []);

        $privateScopes = $this->configurationService->getOpenIDPrivateScopes();

        $claimSet = [];
        $allowedMultipleValueClaims = [];

        /**
         * @var string $scopeName
         * @var array $scopeConfig
         */
        foreach ($privateScopes as $scopeName => $scopeConfig) {
            $claims = is_array($scopeConfig['claims']) ? $scopeConfig['claims'] : [];

            if ($this->isScopeClaimNamePrefixSet($scopeConfig)) {
                $prefix = (string)($scopeConfig[self::CONFIG_KEY_CLAIM_NAME_PREFIX] ?? '');

                $translatorTable = $this->applyPrefixToTranslatorTableKeys($translatorTable, $claims, $prefix);
                $claims = $this->applyPrefixToClaimNames($claims, $prefix);
            }

            $claimSet[] = new ClaimSetEntity($scopeName, $claims);

            if ($this->doesScopeAllowMultipleClaimValues($scopeConfig)) {
                $allowedMultipleValueClaims = array_merge($allowedMultipleValueClaims, $claims);
            }
        }

        $userIdAttr = $this->configurationService->getOpenIDConnectConfiguration()->getString('useridattr');

        return new ClaimTranslatorExtractor($userIdAttr, $claimSet, $translatorTable, $allowedMultipleValueClaims);
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
        /**
         * @var string $claimKey
         * @var array $mapping
         */
        foreach ($translatorTable as $claimKey => $mapping) {
            if (in_array($claimKey, $claims)) {
                $prefixedClaimKey = $prefix . $claimKey;
                $translatorTable[$prefixedClaimKey] = $mapping;
                unset($translatorTable[$claimKey]);
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
        array_walk($claims, function (string &$value, mixed $key, string $prefix) {
            $value = $prefix . $value;
        }, $prefix);

        return $claims;
    }

    /**
     * Check if the scope has a claim name prefix set
     */
    protected function isScopeClaimNamePrefixSet(array $scopeConfig): bool
    {
        return isset($scopeConfig[self::CONFIG_KEY_CLAIM_NAME_PREFIX]) &&
            is_string($scopeConfig[self::CONFIG_KEY_CLAIM_NAME_PREFIX]) &&
            !empty($scopeConfig[self::CONFIG_KEY_CLAIM_NAME_PREFIX]);
    }

    /**
     * Check if the scope allows claims to have multiple values.
     */
    protected function doesScopeAllowMultipleClaimValues(array $scopeConfig): bool
    {
        return isset($scopeConfig[self::CONFIG_KEY_MULTIPLE_CLAIM_VALUES_ALLOWED]) &&
            boolval($scopeConfig[self::CONFIG_KEY_MULTIPLE_CLAIM_VALUES_ALLOWED]);
    }
}

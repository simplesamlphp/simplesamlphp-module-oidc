<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

class ClaimTranslatorExtractorFactory
{
    protected const string CONFIG_KEY_CLAIM_NAME_PREFIX = 'claim_name_prefix';

    protected const string CONFIG_KEY_MULTIPLE_CLAIM_VALUES_ALLOWED = 'are_multiple_claim_values_allowed';


    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly ClaimSetEntityFactory $claimSetEntityFactory,
    ) {
    }


    /**
     * The identity claims and the access token claims are checked here rather than in ModuleConfig, since this
     * is the only place which knows the effective translation table: the defaults with the configured table
     * merged over them and the per-scope claim name prefixes applied. ModuleConfig checks the raw options.
     *
     * @throws \Exception
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function build(): ClaimTranslatorExtractor
    {
        $identityClaims = $this->moduleConfig->getIdentityClaims();
        $claimTranslatorExtractor = $this->buildWith($identityClaims);

        $this->ensureIdentityClaimsAreTranslated($claimTranslatorExtractor, $identityClaims);
        $this->ensureAccessTokenClaimsAreTranslated($claimTranslatorExtractor);

        return $claimTranslatorExtractor;
    }


    /**
     * The check build() runs for the identity claims option, on its own: a fault in the access token claims
     * option does not fail it. For a screen which reports each option in its place.
     *
     * @throws \Exception
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function checkIdentityClaims(): void
    {
        $identityClaims = $this->moduleConfig->getIdentityClaims();

        $this->ensureIdentityClaimsAreTranslated($this->buildWith($identityClaims), $identityClaims);
    }


    /**
     * The check build() runs for the access token claims option, on its own: the effective translation table
     * does not depend on the identity claims, so a fault in that option does not fail it.
     *
     * @throws \Exception
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function checkAccessTokenClaims(): void
    {
        $this->ensureAccessTokenClaimsAreTranslated($this->buildWith([]));
    }


    /**
     * The effective translation table, which is buildable whatever the two claim options say.
     *
     * @throws \Exception
     */
    public function effectiveTranslationTable(): array
    {
        return $this->buildWith([])->getTranslationTable();
    }


    /**
     * @param string[] $identityClaims
     * @throws \Exception
     */
    protected function buildWith(array $identityClaims): ClaimTranslatorExtractor
    {
        $translatorTable = $this->moduleConfig->config()
            ->getOptionalArray(ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE, []);

        $privateScopes = $this->moduleConfig->getPrivateScopes();

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

            $claimSet[] = $this->claimSetEntityFactory->build($scopeName, $claims);

            if ($this->doesScopeAllowMultipleClaimValues($scopeConfig)) {
                $allowedMultipleValueClaims = array_merge($allowedMultipleValueClaims, $claims);
            }
        }

        $userIdAttrs = $this->moduleConfig->getUserIdentifierAttributes();

        return new ClaimTranslatorExtractor(
            $userIdAttrs,
            $this->claimSetEntityFactory,
            $claimSet,
            $translatorTable,
            $allowedMultipleValueClaims,
            $identityClaims,
        );
    }


    /**
     * @param string[] $identityClaims
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function ensureIdentityClaimsAreTranslated(
        ClaimTranslatorExtractor $claimTranslatorExtractor,
        array $identityClaims,
    ): void {
        $this->ensureClaimsAreTranslated(
            ModuleConfig::OPTION_AUTH_IDENTITY_CLAIMS,
            $identityClaims,
            $claimTranslatorExtractor,
        );
        $this->ensureClaimsAreTranslatedToStrings(
            ModuleConfig::OPTION_AUTH_IDENTITY_CLAIMS,
            $identityClaims,
            $claimTranslatorExtractor,
        );
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function ensureAccessTokenClaimsAreTranslated(ClaimTranslatorExtractor $claimTranslatorExtractor): void
    {
        $this->ensureClaimsAreTranslated(
            ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_CLAIMS,
            $this->moduleConfig->getAccessTokenClaims(),
            $claimTranslatorExtractor,
        );
    }


    /**
     * Every claim the option names must have a translation which can yield a value, or it would silently never
     * be released: a name which is not in the effective table, a mapping with no attribute (a default the
     * configuration emptied, or an explicit `'attributes' => []`), or the unprefixed name of a claim a private
     * scope prefixes.
     *
     * @param string[] $claimNames
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function ensureClaimsAreTranslated(
        string $option,
        array $claimNames,
        ClaimTranslatorExtractor $claimTranslatorExtractor,
    ): void {
        foreach ($claimNames as $claimName) {
            if (!$claimTranslatorExtractor->isClaimTranslated($claimName)) {
                throw new ConfigurationError(
                    sprintf(
                        'Invalid value in %s. Claim "%s" has no attribute translation in the effective "%s" table.',
                        $option,
                        $claimName,
                        ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE,
                    ),
                );
            }
        }
    }


    /**
     * An identity claim is 'sub'-like, so its translation must yield a string: a 'json', 'int' or 'bool' type
     * would put a non-string identifier next to 'sub'.
     *
     * @param string[] $claimNames
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function ensureClaimsAreTranslatedToStrings(
        string $option,
        array $claimNames,
        ClaimTranslatorExtractor $claimTranslatorExtractor,
    ): void {
        $translationTable = $claimTranslatorExtractor->getTranslationTable();

        foreach ($claimNames as $claimName) {
            /** @var mixed $mapping */
            $mapping = $translationTable[$claimName] ?? null;
            $type = is_array($mapping) ? ($mapping['type'] ?? 'string') : 'string';

            if ($type !== 'string') {
                throw new ConfigurationError(
                    sprintf(
                        'Invalid value in %s. Claim "%s" is translated to type %s, but an identity claim must ' .
                        'be a string.',
                        $option,
                        $claimName,
                        var_export($type, true),
                    ),
                );
            }
        }
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
            if (in_array($claimKey, $claims, true)) {
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
        $scopeConfig[self::CONFIG_KEY_MULTIPLE_CLAIM_VALUES_ALLOWED];
    }
}

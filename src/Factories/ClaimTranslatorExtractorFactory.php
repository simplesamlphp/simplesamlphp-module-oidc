<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

class ClaimTranslatorExtractorFactory
{
    protected const string CONFIG_KEY_CLAIM_NAME_PREFIX = 'claim_name_prefix';

    /**
     * The claims the JWT access token profile defines for authorization decisions (RFC 9068 section 2.2.3.1),
     * each a list (RFC 7643 section 4.1.2). The library's JwtAccessToken holds them to that shape, so an
     * access token carrying one of them as anything else can not be minted -- which is why a configuration
     * translating one of them to a single value or a JSON object is refused here, at configuration time.
     */
    final public const array ACCESS_TOKEN_LIST_CLAIMS = [
        ClaimsEnum::Groups->value,
        ClaimsEnum::Roles->value,
        ClaimsEnum::Entitlements->value,
    ];


    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly ClaimSetEntityFactory $claimSetEntityFactory,
    ) {
    }


    /**
     * The multi-value settings of the translation table, the identity claims and the access token claims are
     * checked here rather than in ModuleConfig, since this is the only place which knows the effective
     * translation table: the defaults with the configured table merged over them and the per-scope claim name
     * prefixes applied. ModuleConfig checks the raw options.
     *
     * @throws \Exception
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function build(): ClaimTranslatorExtractor
    {
        $identityClaims = $this->moduleConfig->getIdentityClaims();
        $claimTranslatorExtractor = $this->buildWith($identityClaims);

        $this->ensureMultiValuedSettingsAreValid($claimTranslatorExtractor->getTranslationTable());
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
     * The effective translation table, which is buildable whatever the two claim options say. Its multi-value
     * settings are checked as build() checks them, so a fault in the table is reported with the table.
     *
     * @throws \Exception
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function effectiveTranslationTable(): array
    {
        $translationTable = $this->buildWith([])->getTranslationTable();

        $this->ensureMultiValuedSettingsAreValid($translationTable);

        return $translationTable;
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
        }

        $userIdAttrs = $this->moduleConfig->getUserIdentifierAttributes();

        return new ClaimTranslatorExtractor(
            $userIdAttrs,
            $this->claimSetEntityFactory,
            $claimSet,
            $translatorTable,
            $identityClaims,
        );
    }


    /**
     * A claim's multi-value setting (ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED) is true or false, and
     * `true`, a list, is refused where it can not be honoured: on a 'json' mapping, which yields a JSON object,
     * and on an OpenID Connect standard claim or a member of one, which the module releases as a single value.
     * The extractor would release a standard claim as a single value whatever its entry says, so an explicit
     * `true` is refused rather than silently ignored. Read on the effective table, so a claim which a private
     * scope prefixes is checked under its prefixed name, which is no standard claim's; and a member of a 'json'
     * claim is no standard claim whatever its name.
     *
     * @param string|null $standardClaim The standard claim the table's entries are members of, if any.
     * @param string $parentPath The claim the entries are members of, with a trailing dot; '' for the table.
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function ensureMultiValuedSettingsAreValid(
        array $translationTable,
        ?string $standardClaim = null,
        string $parentPath = '',
    ): void {
        /** @var mixed $mapping */
        foreach ($translationTable as $claim => $mapping) {
            if (!is_array($mapping)) {
                continue;
            }

            $path = $parentPath . $claim;
            $isStandardClaim = $parentPath === '' &&
            in_array($claim, ClaimTranslatorExtractor::MANDATORY_SINGLE_VALUE_CLAIMS, true);
            $ownStandardClaim = $standardClaim ?? ($isStandardClaim ? $path : null);
            // Read the way ClaimTranslatorExtractor reads it.
            $type = (string)($mapping['type'] ?? 'string');

            if (array_key_exists(ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED, $mapping)) {
                $this->ensureMultiValuedSettingIsValid(
                    $path,
                    $mapping[ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED],
                    $type,
                    $ownStandardClaim,
                );
            }

            /** @var mixed $members */
            $members = $mapping['claims'] ?? null;

            if ($type === 'json' && is_array($members)) {
                $this->ensureMultiValuedSettingsAreValid($members, $ownStandardClaim, $path . '.');
            }
        }
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function ensureMultiValuedSettingIsValid(
        string $path,
        mixed $multiValued,
        string $type,
        ?string $standardClaim,
    ): void {
        if (!is_bool($multiValued)) {
            throw new ConfigurationError(
                sprintf(
                    'Invalid value in %s. Claim "%s" sets "%s" to a value of type %s; it takes true (the claim is ' .
                    'a list) or false (a single value).',
                    ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE,
                    $path,
                    ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED,
                    get_debug_type($multiValued),
                ),
            );
        }

        if (!$multiValued) {
            return;
        }

        if ($type === 'json') {
            throw new ConfigurationError(
                sprintf(
                    'Invalid value in %s. Claim "%s" sets "%s" to true, but it is translated to type \'json\', ' .
                    'which yields a JSON object, not a list.',
                    ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE,
                    $path,
                    ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED,
                ),
            );
        }

        if ($standardClaim === null) {
            return;
        }

        throw new ConfigurationError(
            sprintf(
                'Invalid value in %s. Claim "%s" sets "%s" to true, but %s an OpenID Connect standard claim ' .
                '(OpenID Connect Core 1.0 section 5.1), which is a single value.',
                ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE,
                $path,
                ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED,
                $path === $standardClaim ? 'it is' : sprintf('it is part of "%s",', $standardClaim),
            ),
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
        $this->ensureNoAccessTokenListClaim(ModuleConfig::OPTION_AUTH_IDENTITY_CLAIMS, $identityClaims);
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function ensureAccessTokenClaimsAreTranslated(ClaimTranslatorExtractor $claimTranslatorExtractor): void
    {
        $accessTokenClaims = $this->moduleConfig->getAccessTokenClaims();

        $this->ensureClaimsAreTranslated(
            ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_CLAIMS,
            $accessTokenClaims,
            $claimTranslatorExtractor,
        );
        $this->ensureAccessTokenListClaimsAreTranslatedToLists(
            ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_CLAIMS,
            $accessTokenClaims,
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
     * would put a non-string identifier next to 'sub'. And a single one: the extractor keeps an identity claim a
     * single value whatever its entry says, so an entry which makes it a list is refused rather than ignored.
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

            if (
                is_array($mapping) &&
                ($mapping[ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED] ?? null) === true
            ) {
                throw new ConfigurationError(
                    sprintf(
                        'Invalid value in %s. Claim "%s" sets "%s" to true in the "%s" table, but an identity ' .
                        'claim is a single value.',
                        $option,
                        $claimName,
                        ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED,
                        ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE,
                    ),
                );
            }
        }
    }


    /**
     * One of ACCESS_TOKEN_LIST_CLAIMS is placed in the access token as a list, or the token can not be minted:
     * its translation has to yield one, which a 'json' mapping (a JSON object) never does and any other
     * mapping does only when it sets ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED to true.
     *
     * @param string[] $claimNames
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function ensureAccessTokenListClaimsAreTranslatedToLists(
        string $option,
        array $claimNames,
        ClaimTranslatorExtractor $claimTranslatorExtractor,
    ): void {
        $translationTable = $claimTranslatorExtractor->getTranslationTable();

        foreach (array_intersect($claimNames, self::ACCESS_TOKEN_LIST_CLAIMS) as $claimName) {
            /** @var mixed $mapping */
            $mapping = $translationTable[$claimName] ?? null;
            // Read the way ClaimTranslatorExtractor reads it.
            $type = is_array($mapping) ? (string)($mapping['type'] ?? 'string') : 'string';

            if ($type === 'json') {
                throw new ConfigurationError(
                    sprintf(
                        'Invalid value in %s. Claim "%s" is a list in a JWT access token (RFC 9068 section ' .
                        '2.2.3.1), but it is translated to type %s, which yields a JSON object.',
                        $option,
                        $claimName,
                        var_export($type, true),
                    ),
                );
            }

            if ($claimTranslatorExtractor->isSingleValueClaim($claimName)) {
                throw new ConfigurationError(
                    sprintf(
                        'Invalid value in %s. Claim "%s" is a list in a JWT access token (RFC 9068 section ' .
                        '2.2.3.1), but its translation yields a single value -- set "%s" to true on its entry ' .
                        'in the "%s" table.',
                        $option,
                        $claimName,
                        ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED,
                        ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE,
                    ),
                );
            }
        }
    }


    /**
     * An identity claim is single-valued like 'sub', so it can not be one of ACCESS_TOKEN_LIST_CLAIMS: the
     * access token would carry it as a string where the profile has a list, and could not be minted.
     *
     * @param string[] $claimNames
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function ensureNoAccessTokenListClaim(string $option, array $claimNames): void
    {
        $listClaims = array_intersect($claimNames, self::ACCESS_TOKEN_LIST_CLAIMS);

        if ($listClaims === []) {
            return;
        }

        throw new ConfigurationError(
            sprintf(
                'Invalid value in %s. Claim "%s" is a list in a JWT access token (RFC 9068 section 2.2.3.1), ' .
                'and an identity claim is a single value.',
                $option,
                reset($listClaims),
            ),
        );
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
}

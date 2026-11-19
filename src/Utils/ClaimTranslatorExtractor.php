<?php

/**
 * This file contains modified code from the 'steverhoades/oauth2-openid-connect-server' library
 * (https://github.com/steverhoades/oauth2-openid-connect-server), with original author, copyright notice and licence:
 * @author Steve Rhoades <sedonami@gmail.com>
 * @copyright (\c) 2018 Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 */

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use Stringable;

class ClaimTranslatorExtractor
{
    /**
     * From JSON Web Token Claims registry: https://www.iana.org/assignments/jwt/jwt.xhtml
     */
    final public const array REGISTERED_CLAIMS = [
        'iss',
        'sub',
        'aud',
        'exp',
        'nbf',
        'iat',
        'jti',
        'azp',
        'nonce',
        'auth_time',
        'at_hash',
        'c_hash',
        'acr',
        'amr',
        'sub_jwk',
    ];

    /**
     * As per https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
     */
    final public const array MANDATORY_SINGLE_VALUE_CLAIMS = [
        'sub',
        'name',
        'given_name',
        'family_name',
        'middle_name',
        'nickname',
        'preferred_username',
        'profile',
        'picture',
        'website',
        'email',
        'email_verified',
        'gender',
        'birthdate',
        'zoneinfo',
        'locale',
        'phone_number',
        'phone_number_verified',
        'address',
        'updated_at',
    ];

    /**
     * The key of a translation table entry which sets the claim's shape: `true` releases every value of the
     * attribute the claim is read from as a list, even a single one, and `false`, like leaving the key out,
     * releases the first value alone. The shape is the claim's own, so it is the same under every scope which
     * releases the claim. It is read on a member of a 'json' claim too. The standard single-value claims and the
     * identity claims are a single value whatever their entry says (isSingleValueClaim()).
     */
    final public const string MAPPING_KEY_MULTI_VALUED = 'multi_valued';


    /** @var array<string, \SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetEntityInterface> */
    protected array $claimSets = [];

    /** @var string[] */
    protected array $protectedScopes = ['openid', 'profile', 'email', 'address', 'phone'];

    protected array $translationTable = [
        'sub' => [
            'eduPersonPrincipalName',
            'eduPersonTargetedID',
            'eduPersonUniqueId',
        ],
        'name' => [
            'cn',
            'displayName',
        ],
        'family_name' => [
            'sn',
        ],
        'given_name' => [
            'givenName',
        ],
        'middle_name' => [
            // Empty
        ],
        'nickname' => [
            'eduPersonNickname',
        ],
        'preferred_username' => [
            'uid',
        ],
        'profile' => [
            'labeledURI',
            'description',
        ],
        'picture' => [
            // Empty 'jpegPhoto', Previously 'jpegPhoto' however spec calls for an url to photo, not an actual photo.
        ],
        'website' => [
            // Empty
        ],
        'gender' => [
            // Empty
        ],
        'birthdate' => [
            // Empty
        ],
        'zoneinfo' => [
            // Empty
        ],
        'locale' => [
            'preferredLanguage',
        ],
        'updated_at' => [
//            'type' => 'int',
        ],
        'email' => [
            'mail',
        ],
        'email_verified' => [
//            'type' => 'bool',
        ],
        'address' => [
            'type' => 'json',
            'claims' => [
                'formatted' => ['postalAddress'],
            ],
        ],
        'phone_number' => [
            'mobile',
            'telephoneNumber',
            'homePhone',
        ],
        'phone_number_verified' => [
//            'type' => 'bool',
            // Empty
        ],
    ];


    /**
     * ClaimTranslatorExtractor constructor.
     *
     * @param string[] $userIdAttrs Ordered list of candidate user identifier attributes.
     * @param \SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetEntityInterface[] $claimSets
     * @param string[] $identityClaims Claims which identify the subject next to 'sub'. They join the 'openid'
     * claim set, so they are released wherever 'sub' is, and they are translated to a single value like 'sub'
     * whatever their translation table entry says.
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        array $userIdAttrs,
        protected readonly ClaimSetEntityFactory $claimSetEntityFactory,
        array $claimSets = [],
        array $translationTable = [],
        protected array $identityClaims = [],
    ) {
        // By default, add the user identifier attribute(s) as attributes for the
        // 'sub' claim, preserving the configured priority order (the translation
        // resolves to the first present attribute). array_reverse keeps the
        // configured order after successive array_unshift() prepends.
        foreach (array_reverse($userIdAttrs) as $userIdAttr) {
            /** @psalm-suppress MixedArgument */
            array_unshift($this->translationTable['sub'], $userIdAttr);
        }

        $this->translationTable = array_merge($this->translationTable, $translationTable);

        // The 'openid' scope releases the subject: 'sub' and, next to it, the configured identity claims.
        $this->addClaimSet($this->claimSetEntityFactory->build('openid', array_values(array_unique([
            'sub',
            ...$this->identityClaims,
        ]))));

        // Add Default OpenID Connect Claims
        // @see http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
        $this->addClaimSet(
            $this->claimSetEntityFactory->build('profile', [
                'name',
                'family_name',
                'given_name',
                'middle_name',
                'nickname',
                'preferred_username',
                'profile',
                'picture',
                'website',
                'gender',
                'birthdate',
                'zoneinfo',
                'locale',
                'updated_at',
            ]),
        );
        $this->addClaimSet(
            $this->claimSetEntityFactory->build('email', [
                'email',
                'email_verified',
            ]),
        );
        $this->addClaimSet(
            $this->claimSetEntityFactory->build('address', [
                'address',
            ]),
        );
        $this->addClaimSet(
            $this->claimSetEntityFactory->build('phone', [
                'phone_number',
                'phone_number_verified',
            ]),
        );

        foreach ($claimSets as $claimSet) {
            $this->addClaimSet($claimSet);
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function addClaimSet(ClaimSetEntityInterface $claimSet): self
    {
        $scope = $claimSet->getScope();

        if (in_array($scope, $this->protectedScopes, true) && isset($this->claimSets[$scope])) {
            throw OidcServerException::serverError(
                sprintf("%s is a protected scope and is pre-defined by the OpenID Connect specification.", $scope),
            );
        }

        $this->claimSets[$scope] = $claimSet;

        return $this;
    }


    public function getClaimSet(string $scope): ?ClaimSetEntityInterface
    {
        if (!$this->hasClaimSet($scope)) {
            return null;
        }

        return $this->claimSets[$scope];
    }


    public function hasClaimSet(string $scope): bool
    {
        return array_key_exists($scope, $this->claimSets);
    }


    /**
     * Get the effective SAML attribute to OIDC claim translation table, that is, the default table
     * with the configured one merged over it, the user identifier attributes prepended to the 'sub'
     * claim, and any per-scope claim name prefixes already applied. Primarily intended for the
     * administrative configuration overview.
     *
     * @return array
     */
    public function getTranslationTable(): array
    {
        return $this->translationTable;
    }


    /**
     * @param string $parentPath The 'json' claim whose members the table holds, with a trailing dot, or '' when it
     * holds claims: a member's shape is read from its own entry alone, since its name is not a claim's.
     * @throws \RuntimeException When the attribute a claim is read from, or a value of it, can not be translated
     * (translateAttribute(), convertType()).
     */
    private function translateSamlAttributesToClaims(
        array $translationTable,
        array $samlAttributes,
        string $parentPath = '',
    ): array {
        $claims = [];
        /**
         * @var string $claim
         * @var array $mappingConfig
         */
        foreach ($translationTable as $claim => $mappingConfig) {
            $path = $parentPath . $claim;
            $isSingleValue = $parentPath !== '' ?
            !$this->isMultiValuedMapping($mappingConfig) :
            $this->isSingleValueMapping($claim, $mappingConfig);
            $type = (string)($mappingConfig['type'] ?? 'string');
            // Neither key names an attribute, which the legacy style below would take it for.
            unset($mappingConfig['type'], $mappingConfig[self::MAPPING_KEY_MULTI_VALUED]);
            if ($type === 'json') {
                $mappingConfigClaims = is_array($mappingConfig['claims']) ? $mappingConfig['claims'] : [];
                $subClaims = $this->translateSamlAttributesToClaims(
                    $mappingConfigClaims,
                    $samlAttributes,
                    $path . '.',
                );
                $claims[$claim] = $subClaims;
                continue;
            }
            // Look for attributes in the attribute key, if not set then assume to legacy style configuration
            $attributes = isset($mappingConfig['attributes']) && is_array($mappingConfig['attributes']) ?
            $mappingConfig['attributes'] :
            $mappingConfig;

            /** @var int|string $samlMatch */
            foreach ($attributes as $samlMatch) {
                if (array_key_exists($samlMatch, $samlAttributes)) {
                    /** @psalm-suppress MixedAssignment */
                    $claims[$claim] = $this->translateAttribute(
                        $type,
                        $isSingleValue,
                        $samlAttributes[$samlMatch],
                        $path,
                        (string)$samlMatch,
                    );
                    break;
                }
            }
        }
        return $claims;
    }


    /**
     * A claim's value from the attribute it is read from: the attribute's first value for a single-valued claim,
     * otherwise a list of all its values in order, each converted to the claim's type; the attribute's keys play no
     * part. Two shapes an authentication processing filter can set are refused: an attribute which is not an array
     * of values, which has no first value to take and would make a list claim a single value, and a value which is
     * an array, which would make a single-valued claim a list and a list claim a list holding a list. Only the
     * values the claim releases are looked at, so a single-valued claim does not fail on a later value. The error
     * names the claim and the attribute, not the value, which is the user's.
     *
     * @param string $claimPath The claim, or a member of a 'json' claim as `claim.member`.
     * @throws \RuntimeException
     */
    private function translateAttribute(
        string $type,
        bool $isSingleValue,
        mixed $attributeValues,
        string $claimPath,
        string $attribute,
    ): mixed {
        if (!is_array($attributeValues)) {
            throw new RuntimeException(
                sprintf(
                    "The '%s' claim can not be translated: attribute '%s' is not an array of values",
                    $claimPath,
                    $attribute,
                ),
            );
        }

        if ($isSingleValue) {
            // The first value wherever the array's internal pointer is, read without copying the array; false for
            // an attribute with no value.
            $firstKey = array_key_first($attributeValues);
            $releasedValues = [$firstKey === null ? false : $attributeValues[$firstKey]];
        } else {
            $releasedValues = $attributeValues;
        }

        $values = [];

        /** @psalm-suppress MixedAssignment */
        foreach ($releasedValues as $value) {
            if (is_array($value)) {
                throw new RuntimeException(
                    sprintf(
                        "The '%s' claim can not be translated: a value of attribute '%s' is an array, not a " .
                        'single value',
                        $claimPath,
                        $attribute,
                    ),
                );
            }

            /** @psalm-suppress MixedAssignment */
            $values[] = $this->convertType($type, $value);
        }

        return $isSingleValue ? reset($values) : $values;
    }


    /**
     * A claim is translated to its first attribute value unless its translation table entry sets
     * MAPPING_KEY_MULTI_VALUED to true -- and the standard single-value claims and the identity claims are a single
     * value whatever their entry says: an identity claim is 'sub'-like in every location it appears in. The factory
     * refuses such an entry at configuration time; this holds for an extractor built without it.
     */
    public function isSingleValueClaim(int|string $claim): bool
    {
        return $this->isSingleValueMapping($claim, $this->translationTable[$claim] ?? null);
    }


    private function isSingleValueMapping(int|string $claim, mixed $mappingConfig): bool
    {
        return in_array($claim, self::MANDATORY_SINGLE_VALUE_CLAIMS, true) ||
        in_array($claim, $this->identityClaims, true) ||
        !$this->isMultiValuedMapping($mappingConfig);
    }


    /**
     * Only `true` makes a list: any other value, which the factory refuses, leaves a single value.
     */
    private function isMultiValuedMapping(mixed $mappingConfig): bool
    {
        return is_array($mappingConfig) && ($mappingConfig[self::MAPPING_KEY_MULTI_VALUED] ?? null) === true;
    }


    /**
     * Converts a single attribute value to the claim's type; translateAttribute() has refused a value which is an
     * array.
     *
     * @throws \RuntimeException
     */
    private function convertType(string $type, mixed $value): mixed
    {
        switch ($type) {
            case 'string':
                if (is_scalar($value) || $value instanceof Stringable) {
                    return (string)$value;
                }

                throw new RuntimeException(
                    sprintf('Cannot safely convert %s to string', get_debug_type($value)),
                );
            case 'int':
                if (is_numeric($value)) {
                    return (int)$value;
                } else {
                    throw new RuntimeException("Cannot convert '$value' to int");
                }
            case 'bool':
                return filter_var($value, FILTER_VALIDATE_BOOLEAN);
        }
        return $value;
    }


    /**
     * The claims the given scopes release, translated from the user's attributes, scope by scope. Only those claims
     * are translated: an attribute value which can not be converted fails the translation of its claim, and must
     * not fail a release which does not include that claim.
     *
     * @param array<array-key, string|\League\OAuth2\Server\Entities\ScopeEntityInterface> $scopes
     * @param string[]|null $claimNames When given, only these of the claims the scopes release are translated and
     * returned, for a caller which carries no others.
     * @throws \RuntimeException When the value of a claim translated here can not be converted to its type, or a
     * released 'sub' or identity claim is not a non-empty string.
     */
    public function extract(array $scopes, array $claims, ?array $claimNames = null): array
    {
        $claimSets = [];
        $releasedClaimNames = [];

        foreach ($scopes as $scope) {
            $scopeName = ($scope instanceof ScopeEntityInterface) ? $scope->getIdentifier() : $scope;

            $claimSet = $this->getClaimSet($scopeName);
            if (null === $claimSet) {
                continue;
            }

            $claimSets[] = $claimSet;
            /** @psalm-suppress MixedAssignment */
            foreach ($claimSet->getClaims() as $claimName) {
                if ($this->isReleasableClaimName($claimName)) {
                    $releasedClaimNames[$claimName] = true;
                }
            }
        }

        if ($claimNames !== null) {
            $releasedClaimNames = array_intersect_key($releasedClaimNames, array_fill_keys($claimNames, true));
        }

        $claims = $this->translateSamlAttributesToClaims(
            array_intersect_key($this->translationTable, $releasedClaimNames),
            $claims,
        );

        $claimData  = [];
        $keys       = array_keys($claims);

        foreach ($claimSets as $claimSet) {
            $intersected = array_intersect($claimSet->getClaims(), $keys);

            if (empty($intersected)) {
                continue;
            }

            $data = array_filter(
                $claims,
                fn($key) => in_array($key, $intersected, true),
                ARRAY_FILTER_USE_KEY,
            );

            $claimData = array_merge($claimData, $data);
        }

        $this->validateSubjectLikeClaims($claimData);

        return $claimData;
    }


    /**
     * The 'sub' claim alone, for a caller which needs the subject and nothing else -- matching an `id_token_hint`
     * before the authentication processing filters have run, storing the RP association. The identity claims are
     * neither translated nor validated here, so an attribute a filter has yet to supply, or an invalid value of
     * one, can not fail a comparison of subjects. A mapped 'sub' which is not a non-empty string is refused as it
     * is in extract(). Null when the 'sub' mapping yields nothing.
     */
    public function extractSubject(array $claims): ?string
    {
        $subjectClaim = $this->translateSamlAttributesToClaims(
            ['sub' => $this->translationTable['sub'] ?? []],
            $claims,
        );

        $this->validateSubjectLikeClaims($subjectClaim);

        return isset($subjectClaim['sub']) ? (string)$subjectClaim['sub'] : null;
    }


    public function extractAdditionalIdTokenClaims(?array $claimsRequest, array $claims): array
    {
        /** @var array $idTokenClaims */
        $idTokenClaims = $claimsRequest['id_token'] ?? [];
        return $this->extractAdditionalClaims($idTokenClaims, $claims);
    }


    public function extractAdditionalUserInfoClaims(?array $claimsRequest, array $claims): array
    {
        /** @var array $userInfoClaims */
        $userInfoClaims = $claimsRequest['userinfo'] ?? [];
        return $this->extractAdditionalClaims($userInfoClaims, $claims);
    }


    /**
     * Add any individually requested claims. Only those are translated, as in extract(), so an attribute value
     * which can not be converted fails only a request which asks for its claim.
     * @link https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
     * @param array $requestedClaims keys are requested claims, value is array of additional info on the request
     */
    private function extractAdditionalClaims(array $requestedClaims, array $claims): array
    {
        if (empty($requestedClaims)) {
            return [];
        }

        $additionalClaims = $this->translateSamlAttributesToClaims(
            array_intersect_key(
                $this->translationTable,
                array_filter(
                    $requestedClaims,
                    $this->isReleasableClaimName(...),
                    ARRAY_FILTER_USE_KEY,
                ),
            ),
            $claims,
        );

        $this->validateSubjectLikeClaims($additionalClaims);

        return $additionalClaims;
    }


    /**
     * Whether a claim set or a claims request names a claim the extractor releases: a non-empty string which PHP
     * keeps as a string array key. PHP turns a decimal integer string such as '0' into an integer key, and the
     * ID token and the access token place claims under string names only.
     *
     * @psalm-assert-if-true non-empty-string $claimName
     */
    private function isReleasableClaimName(mixed $claimName): bool
    {
        return is_string($claimName) && $claimName !== '' && (string)(int)$claimName !== $claimName;
    }


    /**
     * 'sub' and the identity claims identify the End-User, so each one released must be a non-empty string. The
     * translation can not guarantee that on its own: an attribute with no value, or with an empty first value,
     * yields '', and a type other than 'string' (the factory refuses one on an identity claim) need not yield a
     * string.
     */
    private function validateSubjectLikeClaims(array $claims): void
    {
        foreach (['sub', ...$this->identityClaims] as $claim) {
            if (
                array_key_exists($claim, $claims) &&
                (!is_string($claims[$claim]) || $claims[$claim] === '')
            ) {
                throw new RuntimeException(
                    $claim === 'sub' ?
                    "The 'sub' claim must be a non-empty string" :
                    sprintf("The '%s' identity claim must be a non-empty string", $claim),
                );
            }
        }
    }


    /**
     * Get supported claims for this OP. This will return all the claims for which the "SAML attribute to OIDC claim
     * translation" has been defined in module config, meaning it is expected for OP to release those claims. The
     * multi-value setting is no translation: an entry which holds it alone is left out, since an entry replaces the
     * default one whole and so leaves the claim no attribute to read. So is an entry under a name the extractor
     * never releases (isReleasableClaimName()).
     */
    public function getSupportedClaims(): array
    {
        return array_keys(array_filter(
            $this->translationTable,
            fn(mixed $mappingConfig, int|string $claim): bool => $this->isReleasableClaimName($claim) && !empty(
                is_array($mappingConfig) ?
                array_diff_key($mappingConfig, [self::MAPPING_KEY_MULTI_VALUED => null]) :
                $mappingConfig
            ),
            ARRAY_FILTER_USE_BOTH,
        ));
    }


    /**
     * Whether the claim has a translation which can yield a value, read the way translateSamlAttributesToClaims()
     * reads it: at least one attribute to look for, or for a 'json' claim at least one sub-claim. Stricter than
     * getSupportedClaims(), which lists every non-empty entry, so `'attributes' => []` counts as no translation.
     */
    public function isClaimTranslated(string $claim): bool
    {
        return $this->isMappingTranslated($this->translationTable[$claim] ?? null);
    }


    /**
     * A 'json' mapping counts when at least one of its sub-claims does, all the way down: `'claims' =>
     * ['level' => []]` has a sub-claim and still translates nothing.
     */
    private function isMappingTranslated(mixed $mappingConfig): bool
    {
        if (!is_array($mappingConfig)) {
            return false;
        }

        $type = (string)($mappingConfig['type'] ?? 'string');
        unset($mappingConfig['type'], $mappingConfig[self::MAPPING_KEY_MULTI_VALUED]);

        if ($type === 'json') {
            /** @var mixed $subClaims */
            $subClaims = $mappingConfig['claims'] ?? null;

            if (!is_array($subClaims)) {
                return false;
            }

            /** @psalm-suppress MixedAssignment */
            foreach ($subClaims as $subClaimMapping) {
                if ($this->isMappingTranslated($subClaimMapping)) {
                    return true;
                }
            }

            return false;
        }

        $attributes = isset($mappingConfig['attributes']) && is_array($mappingConfig['attributes']) ?
        $mappingConfig['attributes'] :
        $mappingConfig;

        return $attributes !== [];
    }
}

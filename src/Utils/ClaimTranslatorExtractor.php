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
     * whatever the multi-value setting of a scope which also carries them.
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        array $userIdAttrs,
        protected readonly ClaimSetEntityFactory $claimSetEntityFactory,
        array $claimSets = [],
        array $translationTable = [],
        protected array $allowedMultiValueClaims = [],
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


    private function translateSamlAttributesToClaims(array $translationTable, array $samlAttributes): array
    {
        $claims = [];
        /**
         * @var string $claim
         * @var array $mappingConfig
         */
        foreach ($translationTable as $claim => $mappingConfig) {
            $type = (string)($mappingConfig['type'] ?? 'string');
            unset($mappingConfig['type']);
            if ($type === 'json') {
                $mappingConfigClaims = is_array($mappingConfig['claims']) ? $mappingConfig['claims'] : [];
                $subClaims = $this->translateSamlAttributesToClaims($mappingConfigClaims, $samlAttributes);
                $claims[$claim] = $subClaims;
                continue;
            }
            // Look for attributes in the attribute key, if not set then assume to legacy style configuration
            $attributes = isset($mappingConfig['attributes']) && is_array($mappingConfig['attributes']) ?
            $mappingConfig['attributes'] :
            $mappingConfig;

            /** @var string $samlMatch */
            foreach ($attributes as $samlMatch) {
                if (array_key_exists($samlMatch, $samlAttributes)) {
                    /** @psalm-suppress MixedAssignment, MixedArgument */
                    $values = $this->isSingleValueClaim($claim) ?
                    current($samlAttributes[$samlMatch]) :
                    $samlAttributes[$samlMatch];
                    /** @psalm-suppress MixedAssignment */
                    $claims[$claim] = $this->convertType($type, $values);
                    break;
                }
            }
        }
        return $claims;
    }


    /**
     * A claim is translated to its first attribute value unless a scope allows it multiple values -- and the
     * standard single-value claims and the identity claims are never allowed them: an identity claim is 'sub'-like
     * in every location it appears in, so a multi-value flag on any scope which also carries it (granted or not:
     * translation happens before the scope filtering) must not turn it into an array.
     */
    public function isSingleValueClaim(int|string $claim): bool
    {
        return in_array($claim, self::MANDATORY_SINGLE_VALUE_CLAIMS, true) ||
        in_array($claim, $this->identityClaims, true) ||
        !in_array($claim, $this->allowedMultiValueClaims, true);
    }


    private function convertType(string $type, mixed $attributes): mixed
    {
        if (is_array($attributes)) {
            $values = [];
            /** @psalm-suppress MixedAssignment */
            foreach ($attributes as $attribute) {
                /** @psalm-suppress MixedAssignment */
                $values[] = $this->convertType($type, $attribute);
            }
            return $values;
        }
        switch ($type) {
            case 'string':
                if (is_scalar($attributes) || $attributes instanceof Stringable) {
                    return (string)$attributes;
                }

                throw new RuntimeException(
                    sprintf('Cannot safely convert %s to string', get_debug_type($attributes)),
                );
            case 'int':
                if (is_numeric($attributes)) {
                    return (int)$attributes;
                } else {
                    throw new RuntimeException("Cannot convert '$attributes' to int");
                }
            case 'bool':
                return filter_var($attributes, FILTER_VALIDATE_BOOLEAN);
        }
        return $attributes;
    }


    /**
     * @param array<array-key, string|\League\OAuth2\Server\Entities\ScopeEntityInterface> $scopes
     */
    public function extract(array $scopes, array $claims): array
    {
        $claims = $this->translateSamlAttributesToClaims($this->translationTable, $claims);

        $claimData  = [];
        $keys       = array_keys($claims);

        foreach ($scopes as $scope) {
            $scopeName = ($scope instanceof ScopeEntityInterface) ? $scope->getIdentifier() : $scope;

            $claimSet = $this->getClaimSet($scopeName);
            if (null === $claimSet) {
                continue;
            }

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
     * Add any individually requested claims
     * @link https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
     * @param array $requestedClaims keys are requested claims, value is array of additional info on the request
     */
    private function extractAdditionalClaims(array $requestedClaims, array $claims): array
    {
        if (empty($requestedClaims)) {
            return [];
        }
        $translatedClaims = $this->translateSamlAttributesToClaims($this->translationTable, $claims);

        $additionalClaims = array_filter(
            $translatedClaims,
            fn(/** @param array-key $key */ $key) => array_key_exists($key, $requestedClaims),
            ARRAY_FILTER_USE_KEY,
        );

        $this->validateSubjectLikeClaims($additionalClaims);

        return $additionalClaims;
    }


    /**
     * 'sub' and the identity claims identify the End-User, so each one released must be a non-empty string. The
     * translation can not guarantee that on its own: an attribute value which is itself an array (an authproc
     * filter can produce one) survives convertType() as an array, and an attribute with no value yields ''.
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
     * translation" has been defined in module config, meaning it is expected for OP to release those claims.
     */
    public function getSupportedClaims(): array
    {
        return array_keys(array_filter($this->translationTable));
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
        unset($mappingConfig['type']);

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

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
 *
 * This file contains modified code from the 'steverhoades/oauth2-openid-connect-server' library
 * (https://github.com/steverhoades/oauth2-openid-connect-server), with original author, copyright notice and licence:
 * @author Steve Rhoades <sedonami@gmail.com>
 * @copyright (c) 2018 Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 */

namespace SimpleSAML\Module\oidc\Utils;

use Lcobucci\JWT\Token\RegisteredClaims;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

class ClaimTranslatorExtractor
{
    /** @var array<string, ClaimSetEntityInterface> */
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
     * From JSON Web Token Claims registry: https://www.iana.org/assignments/jwt/jwt.xhtml
     */
    final public const REGISTERED_CLAIMS = [
        ...RegisteredClaims::ALL,
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
    final public const MANDATORY_SINGLE_VALUE_CLAIMS = [
        'sub',
        // TODO mivanci v7 Uncomment the rest of the claims, as this was a potential breaking change in v6.
//        'name',
//        'given_name',
//        'family_name',
//        'middle_name',
//        'nickname',
//        'preferred_username',
//        'profile',
//        'picture',
//        'website',
//        'email',
//        'email_verified',
//        'gender',
//        'birthdate',
//        'zoneinfo',
//        'locale',
//        'phone_number',
//        'phone_number_verified',
//        'address',
//        'updated_at',
    ];

    /**
     * ClaimTranslatorExtractor constructor.
     *
     * @param \SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetEntityInterface[] $claimSets
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        string $userIdAttr,
        protected readonly ClaimSetEntityFactory $claimSetEntityFactory,
        array $claimSets = [],
        array $translationTable = [],
        protected array $allowedMultiValueClaims = [],
    ) {
        // By default, add the userIdAttribute as one of the attribute for 'sub' claim.
        /** @psalm-suppress MixedArgument */
        array_unshift($this->translationTable['sub'], $userIdAttr);

        $this->translationTable = array_merge($this->translationTable, $translationTable);

        $this->addClaimSet($this->claimSetEntityFactory->build('openid', [
            'sub',
        ]));

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
                    $values =  (!in_array($claim, self::MANDATORY_SINGLE_VALUE_CLAIMS, true)) &&
                    in_array($claim, $this->allowedMultiValueClaims, true) ?
                    $samlAttributes[$samlMatch] :
                    current($samlAttributes[$samlMatch]);
                    /** @psalm-suppress MixedAssignment */
                    $claims[$claim] = $this->convertType($type, $values);
                    break;
                }
            }
        }
        return $claims;
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

        return $claimData;
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

        return array_filter(
            $translatedClaims,
            fn(/** @param array-key $key */ $key) => array_key_exists($key, $requestedClaims),
            ARRAY_FILTER_USE_KEY,
        );
    }

    /**
     * Get supported claims for this OP. This will return all the claims for which the "SAML attribute to OIDC claim
     * translation" has been defined in module config, meaning it is expected for OP to release those claims.
     */
    public function getSupportedClaims(): array
    {
        return array_keys(array_filter($this->translationTable));
    }
}

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

namespace SimpleSAML\Module\oidc;

use Lcobucci\JWT\Token\RegisteredClaims;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Entities\ClaimSetEntity;
use OpenIDConnectServer\Exception\InvalidArgumentException;
use RuntimeException;

class ClaimTranslatorExtractor extends ClaimExtractor
{
    /** @var array */
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
            // Empty 'jpegPhoto', Previously 'jpegPhoto' however spec calls for a url to photo, not an actual photo.
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
            'type' => 'int'
        ],
        'email' => [
            'mail',
        ],
        'email_verified' => [
            'type' => 'bool'
        ],
        'address' => [
            'type' => 'json',
            'claims' => [
                'formatted' => ['postalAddress'],
            ]
        ],
        'phone_number' => [
            'mobile',
            'telephoneNumber',
            'homePhone',
        ],
        'phone_number_verified' => [
            'type' => 'bool'
            // Empty
        ],
    ];

    /**
     * From JSON Web Token Claims registry: https://www.iana.org/assignments/jwt/jwt.xhtml
     */
    public const REGISTERED_CLAIMS = [
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
     * Claims for which it is allowed to have multiple values.
     */
    protected array $allowedMultiValueClaims;

    /**
     * ClaimTranslatorExtractor constructor.
     *
     * @param string $userIdAttr
     * @param ClaimSetEntity[] $claimSets
     * @param array $translationTable
     * @param array $allowedMultipleValueClaims
     * @throws InvalidArgumentException
     */
    public function __construct(
        string $userIdAttr,
        array $claimSets = [],
        array $translationTable = [],
        array $allowedMultipleValueClaims = []
    ) {
        // By default, add the userIdAttribute as one of the attribute for 'sub' claim.
        array_unshift($this->translationTable['sub'], $userIdAttr);

        $this->translationTable = array_merge($this->translationTable, $translationTable);

        $this->allowedMultiValueClaims = $allowedMultipleValueClaims;

        $this->protectedClaims[] = 'openid';
        $this->addClaimSet(new ClaimSetEntity('openid', [
            'sub',
        ]));

        parent::__construct($claimSets);
    }

    /**
     * @param array $translationTable
     * @param array $samlAttributes
     * @return array
     */
    private function translateSamlAttributesToClaims(array $translationTable, array $samlAttributes): array
    {
        $claims = [];
        foreach ($translationTable as $claim => $mappingConfig) {
            $type = $mappingConfig['type'] ?? 'string';
            unset($mappingConfig['type']);
            if ($type === 'json') {
                $subClaims = $this->translateSamlAttributesToClaims($mappingConfig['claims'], $samlAttributes);
                $claims[$claim] = $subClaims;
                continue;
            }
            // Look for attributes in the attribute key, if not set then assume to legacy style configuration
            $attributes = $mappingConfig['attributes'] ?? $mappingConfig;

            foreach ($attributes as $samlMatch) {
                if (array_key_exists($samlMatch, $samlAttributes)) {
                    $values = in_array($claim, $this->allowedMultiValueClaims) ?
                        $samlAttributes[$samlMatch] :
                        current($samlAttributes[$samlMatch]);
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
            foreach ($attributes as $attribute) {
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

    public function extract(array $scopes, array $claims): array
    {
        $translatedClaims = $this->translateSamlAttributesToClaims($this->translationTable, $claims);

        return parent::extract($scopes, $translatedClaims);
    }

    public function extractAdditionalIdTokenClaims(?array $claimsRequest, array $claims): array
    {
        $idTokenClaims = $claimsRequest['id_token'] ?? [];
        return $this->extractAdditionalClaims($idTokenClaims, $claims);
    }

    public function extractAdditionalUserInfoClaims(?array $claimsRequest, array $claims): array
    {
        $userInfoClaims = $claimsRequest['userinfo'] ?? [];
        return $this->extractAdditionalClaims($userInfoClaims, $claims);
    }

    /**
     * Add any individually requested claims
     * @link https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
     * @param array $requestedClaims keys are requested claims, value is array of additional info on the request
     * @param array $claims
     * @return array
     */
    private function extractAdditionalClaims(array $requestedClaims, array $claims): array
    {
        if (empty($requestedClaims)) {
            return [];
        }
        $translatedClaims = $this->translateSamlAttributesToClaims($this->translationTable, $claims);

        return array_filter(
            $translatedClaims,
            function ($key) use ($requestedClaims) {
                return array_key_exists($key, $requestedClaims);
            },
            ARRAY_FILTER_USE_KEY
        );
    }
}

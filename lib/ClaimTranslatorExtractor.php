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

namespace SimpleSAML\Modules\OpenIDConnect;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Entities\ClaimSetEntity;

class ClaimTranslatorExtractor extends ClaimExtractor
{
    /** @var array */
    protected $translationTable = [
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
        'int:updated_at' => [
            // Empty
        ],
        'email' => [
            'mail',
        ],
        'bool:email_verified' => [
            // Empty
        ],
        'address' => [
            'formatted' => ['postalAddress'],
        ],
        'phone_number' => [
            'mobile',
            'telephoneNumber',
            'homePhone',
        ],
        'bool:phone_number_verified' => [
            // Empty
        ],
    ];

    /**
     * Claims for which it is allowed to have multiple values.
     * @var array $allowedMultiValueClaims
     */
    protected $allowedMultiValueClaims;

    /**
     * ClaimTranslatorExtractor constructor.
     *
     * @param ClaimSetEntity[] $claimSets
     *
     * @param array $translationTable
     * @param array $allowedMultipleValueClaims
     * @throws \OpenIDConnectServer\Exception\InvalidArgumentException
     */
    public function __construct(
        array $claimSets = [],
        array $translationTable = [],
        array $allowedMultipleValueClaims = []
    ) {
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
     */
    private function translateSamlAttributesToClaims(array $translationTable, array $samlAttributes): array
    {
        $claims = [];
        foreach ($translationTable as $claim => $mappingConfig) {
            list($type, $claim) = $this->getTypeAndClaimName($claim);
            foreach ($mappingConfig as $key => $samlMatch) {
                if (is_int($key)) {
                    if (\array_key_exists($samlMatch, $samlAttributes)) {
                        $values = in_array($claim, $this->allowedMultiValueClaims) ?
                            $samlAttributes[$samlMatch] :
                            current($samlAttributes[$samlMatch]);
                        $claims[$claim] = $this->convertType($type, $values);
                        break;
                    }
                } else {
                    // These saml attributes translate to json object
                    $subClaims = $this->translateSamlAttributesToClaims($mappingConfig, $samlAttributes);
                    $claims[$claim] = $subClaims;
                    break;
                }
            }
        }
        return $claims;
    }

    private function convertType(string $type, $attributes)
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
                    throw new \RuntimeException("Cannot convert '$attributes' to int");
                }
            case 'bool':
                return filter_var($attributes, FILTER_VALIDATE_BOOLEAN);
        }
        return $attributes;
    }

    /**
     * Look at any optional 'type' prefix on the claim and return the type
     * and the claim name without the prefix
     * @param string $claim A claim name, with an optional type prefix.
     * @return string[] An array [0 => type, 1 => claim name]
     */
    public static function getTypeAndClaimName(string $claim): array
    {
        // check for type conversion prefix
        $parts = explode(':', $claim, 2);
        if (sizeof($parts) !== 2) {
            return ['string', $claim];
        }
        $validTypes = ['int', 'string', 'bool'];
        $type = $parts[0];
        if (in_array($type, $validTypes)) {
            return [$type, $parts[1]];
        }
        // not a valid type. Claim may contain colons( e.g. oid style claims)
        return ['string', $claim];
    }

    public function extract(array $scopes, array $claims): array
    {
        $translatedClaims = $this->translateSamlAttributesToClaims($this->translationTable, $claims);

        return parent::extract($scopes, $translatedClaims);
    }

    public function extractAdditionalIdTokenClaims(?array $claimsRequest, array $claims): array
    {
        $idTokenClaims = $claimsRequest['id_token'] ?? [];
        return $this->extractAdditonalClaims($idTokenClaims, $claims);
    }

    public function extractAdditionalUserInfoClaims(?array $claimsRequest, array $claims): array
    {
        $userInfoClaims = $claimsRequest['userinfo'] ?? [];
        return $this->extractAdditonalClaims($userInfoClaims, $claims);
    }

    /**
     * Add any individually requested claims
     * @link https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
     * @param array $requestedClaims keys are requested claims, value is array of additional info on the request
     * @param array $claims
     * @return array
     */
    private function extractAdditonalClaims(array $requestedClaims, array $claims): array
    {
        if (empty($requestedClaims)) {
            return [];
        }
        $translatedClaims = $this->translateSamlAttributesToClaims($this->translationTable, $claims);

        $data = array_filter(
            $translatedClaims,
            function ($key) use ($requestedClaims) {
                return array_key_exists($key, $requestedClaims);
            },
            ARRAY_FILTER_USE_KEY
        );
        return $data;
    }
}

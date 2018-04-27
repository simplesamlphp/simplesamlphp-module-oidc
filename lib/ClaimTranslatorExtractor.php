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

use OpenIDConnectServer\ClaimExtractor;

class ClaimTranslatorExtractor extends ClaimExtractor
{
    public static $translationTable = [
        'sub' => [
            'eduPersonPrincipalName',
            'eduPersonTargetedID',
            'eduPersonUniqueId',
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
            'jpegPhoto',
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
            // Empty
        ],
        'email' => [
            'mail',
        ],
        'email_verified' => [
            // Empty
        ],
        'address' => [
            'postalAddress',
        ],
        'phone_number' => [
            'mobile',
            'telephoneNumber',
            'homePhone',
        ],
        'phone_number_verified' => [
            // Empty
        ],
    ];

    private function translateSamlAttributesToClaims($samlAttributes)
    {
        $claims = [];

        foreach (self::$translationTable as $claim => $samlMatches) {
            foreach ($samlMatches as $samlMatch) {
                if (array_key_exists($samlMatch, $samlAttributes)) {
                    $claims[$claim] = current($samlAttributes[$samlMatch]);
                    break;
                }
            }
        }

        return $claims;
    }

    public function extract(array $scopes, array $samlAttributes)
    {
        $claims = $this->translateSamlAttributesToClaims($samlAttributes);

        return parent::extract($scopes, $claims);
    }
}

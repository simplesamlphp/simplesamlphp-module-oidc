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

$config = [
    // The private key passphrase (optional)
    // 'pass_phrase' => 'secret',

    // Tokens TTL
    'authCodeDuration' => 'PT10M', // 10 minutes
    'refreshTokenDuration' => 'P1M', // 1 month
    'accessTokenDuration' => 'PT1H', // 1 hour,

    // Tag to run storage cleanup script using the cron module...
    'cron_tag' => 'hourly',

    // Set token signer
    // See Lcobucci\JWT\Signer algorithms in https://github.com/lcobucci/jwt/tree/master/src/Signer
    'signer' => \Lcobucci\JWT\Signer\Rsa\Sha256::class,
    // 'signer' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
    // 'signer' => \Lcobucci\JWT\Signer\Ecdsa\Sha256::class,

    // this is the default auth source used for authentication if the auth source
    // is not specified on particular client
    'auth' => 'default-sp',

    // useridattr is the attribute-name that contains the userid as returned from idp
    'useridattr' => 'uid',

    // You can create as many scopes as you want and assign attributes to them
    'scopes' => [
        /*
         * Optional. You can add more scopes.
         */
//        'private' => [
//            'description' => 'private scope',
//            'claim_name_prefix' => '', // Prefix to apply for all claim names from this scope
//            'are_multiple_claim_values_allowed' => false, // Are claims for this scope allowed to have multiple values
//            'attributes' => ['national_document_id']
//        ],
    ],
    'translate' => [
        /*
         * This is the default translate table from SAML to OIDC.
         * You can change here the behaviour or add more translation to your
         * private attributes scopes
         */
//        'sub' => [
//            'eduPersonPrincipalName',
//            'eduPersonTargetedID',
//            'eduPersonUniqueId',
//        ],
//        'family_name' => [
//            'sn',
//        ],
//        'given_name' => [
//            'givenName',
//        ],
//        'middle_name' => [
//            // Empty
//        ],
//        'nickname' => [
//            'eduPersonNickname',
//        ],
//        'preferred_username' => [
//            'uid',
//        ],
//        'profile' => [
//            'labeledURI',
//            'description',
//        ],
//        'picture' => [
//            'jpegPhoto',
//        ],
//        'website' => [
//            // Empty
//        ],
//        'gender' => [
//            // Empty
//        ],
//        'birthdate' => [
//            // Empty
//        ],
//        'zoneinfo' => [
//            // Empty
//        ],
//        'locale' => [
//            'preferredLanguage',
//        ],
//        'updated_at' => [
//            // Empty
//        ],
//        'email' => [
//            'mail',
//        ],
//        'email_verified' => [
//            // Empty
//        ],
//        'address' => [
//            'postalAddress',
//        ],
//        'phone_number' => [
//            'mobile',
//            'telephoneNumber',
//            'homePhone',
//        ],
//        'phone_number_verified' => [
//            // Empty
//        ],
        /*
         * Optional scopes attributes
         */
//        'national_document_id' => [
//            'schacPersonalUniqueId',
//        ],
    ],
];

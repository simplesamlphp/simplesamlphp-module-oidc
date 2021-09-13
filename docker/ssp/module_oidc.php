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
    'auth' => 'example-userpass',

    // useridattr is the attribute-name that contains the userid as returned from idp
    'useridattr' => 'uid',
    'permissions' => [
        // Attribute to inspect to determine user's permissions
        'attribute' => 'eduPersonEntitlement',
        // Which entitlements allow for registering, editing, delete a client. OIDC clients are owned by the creator
        'client' => ['urn:example:oidc:manage:client'],
    ],

    'alwaysAddClaimsToIdToken' => false,
    // Settings regarding Authentication Processing Filters.
    // Note: OIDC authN state array will not contain all of the keys which are available during SAML authN,
    // like Service Provider metadata, etc.
    //
    // At the moment, the following SAML authN data will be available during OIDC authN in the sate array:
    // - 'Attributes', 'Authority', 'AuthnInstant', 'Expire', 'IdPMetadata', 'Source'
    // In addition to that, the following OIDC related data will be available in the state array:
    // - 'OidcProviderMetadata' - contains information otherwise available from the OIDC configuration URL.
    // - 'OidcRelyingPartyMetadata' - contains information about the OIDC client making the authN request.
    // - 'OidcAuthorizationRequestParameters' - contains relevant authorization request query parameters.
    //
    // List of authproc filters which will run for every OIDC authN. Add filters as described in docs for SAML authproc
    // @see https://simplesamlphp.org/docs/stable/simplesamlphp-authproc
    'authproc.oidc' => [
        // Add authproc filters here
    ],

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
//        'name' => [
//            'cn',
//            'displayName',
//        ],
//        'family_name' => [
//            'sn',
//        ],
//        'given_name' => [
//            'givenName',
//        ],
        'middle_name' => [
            'middle_name'
        ],
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
        'picture' => [
            'jpegURL',
        ],
        'website' => [
            'website'
        ],
        'gender' => [
            'gender'
        ],
        'birthdate' => [
            'birthdate'
        ],
        'zoneinfo' => [
            'zoneinfo'
        ],
//        'locale' => [
//            'preferredLanguage',
//        ],
        'int:updated_at' => [
            'updated_at'
        ],
//        'email' => [
//            'mail',
//        ],
        'bool:email_verified' => [
            'email_verified'
        ],
        'address' => [
            'formatted' => ['postalAddress'],
            'street_address' => ['street_address'],
            'locality' => ['locality'],
            'region' => ['region'],
            'postal_code' => ['postal_code'],
            'country' => ['country'],
        ],

//        'phone_number' => [
//            'mobile',
//            'telephoneNumber',
//            'homePhone',
//        ],
        'bool:phone_number_verified' => [
            'phone_number_verified'
        ],
        /*
         * Optional scopes attributes
         */
//        'national_document_id' => [
//            'schacPersonalUniqueId',
//        ],
    ],
];

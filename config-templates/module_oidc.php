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
    // pagination
    'items_per_page' => 20,

    // The private key passphrase (optional)
    // 'pass_phrase' => 'secret',
    // The cert and key for signing the ID token. Default names are oidc_module.key and oidc_module.crt
    // 'privatekey' => 'oidc_module.key',
    // 'certificate' => 'oidc_module.crt',

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

    // The key id to use in the header. Default is a finger print of the public key
    // 'kid' => 'abcd',


    // this is the default auth source used for authentication if the auth source
    // is not specified on particular client
    'auth' => 'default-sp',

    // useridattr is the attribute-name that contains the userid as returned from idp. By default, this attribute
    // will be dynamically added to the 'sub' claim in the attribute-to-claim translation table (you will probably
    // want to use this attribute as the 'sub' claim since it designates unique identifier for the user).
    'useridattr' => 'uid',

    /**
     * Permissions let the module expose functionality to specific users.
     * In the below configuration, a user's eduPersonEntitlement attribute is examined. If the user
     * tries to do something that requires the 'client' permission (such as registering their own client)
     * then they will need one of the eduPersonEntitlements from the `client` permission array.
     *
     * A permission can be disable by commenting it out.
     */
    'permissions' => [
        // Attribute to inspect to determine user's permissions
        'attribute' => 'eduPersonEntitlement',
        // Which entitlements allow for registering, editing, delete a client. OIDC clients are owned by the creator
        'client' => ['urn:example:oidc:manage:client'],
    ],

    // Settings regarding Authentication Processing Filters.
    // Note: OIDC authN state array will not contain all of the keys which are available during SAML authN,
    // like Service Provider metadata, etc.
    //
    // At the moment, the following SAML authN data will be available during OIDC authN in the sate array:
    // - ['Attributes'], ['Authority'], ['AuthnInstant'], ['Expire']
    // Source and destination will have entity IDs corresponding to the OP issuer ID and Client ID respectively.
    // - ['Source']['entityid'] - contains OpenId Provider issuer ID
    // - ['Destination']['entityid'] - contains Relying Party (OIDC Client) ID
    // In addition to that, the following OIDC related data will be available in the state array:
    // - ['Oidc']['OpenIdProviderMetadata'] - contains information otherwise available from the OIDC configuration URL.
    // - ['Oidc']['RelyingPartyMetadata'] - contains information about the OIDC client making the authN request.
    // - ['Oidc']['AuthorizationRequestParameters'] - contains relevant authorization request query parameters.
    //
    // List of authproc filters which will run for every OIDC authN. Add filters as described in docs for SAML authproc
    // @see https://simplesamlphp.org/docs/stable/simplesamlphp-authproc
    'authproc.oidc' => [
        // Add authproc filters here
    ],

    // Optional custom scopes. You can create as many scopes as you want and assign claims to them.
    'scopes' => [
//        'private' => [ // The key represents the scope name.
//            'description' => 'private scope',
//            'claim_name_prefix' => '', // Prefix to apply for all claim names from this scope
//            'are_multiple_claim_values_allowed' => false, // Are claims for this scope allowed to have multiple values
//            'claims' => ['national_document_id'] // Claims from the translation table which this scope will contain
//        ],
    ],
    'translate' => [
        /*
         * This is the default translate table from SAML to OIDC.
         * You can change here the behaviour or add more translation to your
         * private attributes scopes
         *
         * The basic format is
         *
         * 'claimName' => [
         *     'type' => 'string|int|bool|json',
         *      // For non JSON types
         *     'attributes' => ['samlAttribute1', 'samlAttribute2']
         *      // For JSON types
         *     'claims => [
         *          'subclaim' => [ 'type' => 'string', 'attributes' => ['saml1']]
         *      ]
         *  ]
         *
         * For convenience the default type is "string" so type does not need to be defined.
         * If "attributes" is not set, then it is assumed that the rest of the values are saml
         * attribute names.
         *
         * Note on 'sub' claim: by default, the list of attributes for 'sub' claim will also contain attribute defined
         * in 'useridattr' setting. You will probably want to use this attribute as the 'sub' claim since it
         * designates unique identifier for the user, However, override as necessary.
         */
//        'sub' => [
//            'attribute-defined-in-useridattr', // will be dynamically added if the list for 'sub' claim is not set.
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
//            // Empty. Previously 'jpegPhoto' however spec calls for a url to photo, not an actual photo.
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
//            'type' => 'int',
//            'attributes' => [],
//        ],
//        'email' => [
//            'mail',
//        ],
//        'email_verified' => [
//            'type' => 'bool',
//            'attributes' => [],
//        ],
//         // address is a json object. Set the 'formatted' sub claim to postalAddress
//        'address' => [
//            'type' => 'json',
//            'claims' => [
//                'formatted' => ['postalAddress'],
//            ]
//        ],
//        'phone_number' => [
//            'mobile',
//            'telephoneNumber',
//            'homePhone',
//        ],
//        'phone_number_verified' => [
//            'type' => 'bool',
//            'attributes' => [],
//        ],
        /*
         * Optional scopes attributes
         */
//        'national_document_id' => [
//            'schacPersonalUniqueId',
//        ],
    ],

    // Optional list of the Authentication Context Class References that this OP supports.
    // If populated, this list will be available in OP discovery document (OP Metadata) as 'acr_values_supported'.
    // @see https://datatracker.ietf.org/doc/html/rfc6711
    // @see https://www.iana.org/assignments/loa-profiles/loa-profiles.xhtml
    // @see https://openid.net/specs/openid-connect-core-1_0.html#IDToken (acr claim)
    // @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest (acr_values parameter)
    // Syntax: string[] (array of strings)
    'acrValuesSupported' => [
//        'https://refeds.org/assurance/profile/espresso',
//        'https://refeds.org/assurance/profile/cappuccino',
//        'https://refeds.org/profile/mfa',
//        'https://refeds.org/profile/sfa',
//        'urn:mace:incommon:iap:silver',
//        'urn:mace:incommon:iap:bronze',
//        '4',
//        '3',
//        '2',
//        '1',
//        '0',
//        '...',
    ],

    // If this OP supports ACRs, indicate which usable auth source supports which ACRs.
    // Order of ACRs is important, more important ones being first.
    // Syntax: array<string,string[]> (array with auth source as key and value being array of ACR values as strings)
    'authSourcesToAcrValuesMap' => [
//        'example-userpass' => ['1', '0'],
//        'default-sp' => ['http://id.incommon.org/assurance/bronze', '2', '1', '0'],
//        'strongly-assured-authsource' => [
//            'https://refeds.org/assurance/profile/espresso',
//            'https://refeds.org/profile/mfa',
//            'https://refeds.org/assurance/profile/cappuccino',
//            'https://refeds.org/profile/sfa',
//            '3',
//            '2',
//            '1',
//            '0',
//        ],
    ],

    // If this OP supports ACRs, indicate if authentication using cookie should be forced to specific ACR value.
    // If this option is set to null, no specific ACR will be forced for cookie authentication and the resulting ACR
    // will be one of the ACRs supported on used auth source during authentication, that is, session creation.
    // If this option is set to specific ACR, with ACR value being one of the ACR value this OP supports, it will be
    // set to that ACR for cookie authentication.
    // For example, OIDC Core Spec notes that authentication using a long-lived browser cookie is one example where
    // the use of "level 0" is appropriate:
//     'forcedAcrValueForCookieAuthentication' => '0',
    'forcedAcrValueForCookieAuthentication' => null,
];

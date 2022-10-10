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

    // useridattr is the attribute-name that contains the userid as returned from idp. By default, this attribute
    // will be dynamically added to the 'sub' claim in the attribute-to-claim translation table (you will probably
    // want to use this attribute as the 'sub' claim since it designates unique identifier for the user).
    'useridattr' => 'uid',
    'permissions' => [
        // Attribute to inspect to determine user's permissions
        'attribute' => 'eduPersonEntitlement',
        // Which entitlements allow for registering, editing, delete a client. OIDC clients are owned by the creator
        'client' => ['urn:example:oidc:manage:client'],
    ],

    'alwaysAddClaimsToIdToken' => false,
    'alwaysIssueRefreshToken' => false,

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
        'updated_at' => [
            'type' => 'int',
            'updated_at'
        ],
//        'email' => [
//            'mail',
//        ],
        'email_verified' => [
            'type' => 'bool',
            'attributes' => ['email_verified']
        ],
        'address' => [
            'type' => 'json',
            'claims' => [
                'formatted' => ['postalAddress'],
                'street_address' => ['street_address'],
                'locality' => ['locality'],
                'region' => ['region'],
                'postal_code' => ['postal_code'],
                'country' => ['country'],
            ]
        ],

//        'phone_number' => [
//            'mobile',
//            'telephoneNumber',
//            'homePhone',
//        ],
        'phone_number_verified' => [
            'type' => 'bool',
            'phone_number_verified'
        ],
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
        '1',
        '0',
    ],

    // If this OP supports ACRs, indicate which usable auth source supports which ACRs.
    // Order of ACRs is important, more important ones being first.
    // Syntax: array<string,string[]> (array with auth source as key and value being array of ACR values as strings)
    'authSourcesToAcrValuesMap' => [
        'example-userpass' => ['1', '0'],
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

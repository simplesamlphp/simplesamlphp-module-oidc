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

    // useridattr is the attribute-name that contains the userid as returned from idp
    'useridattr' => 'uid',

    // The claims from the standard scopes should only be put in the ID token when no access token is issued
    // For module backwards compatibility you can always include claims in the id token.
    // See: https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.4
    'alwaysAddClaimsToIdToken' => true,

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
//        'int:updated_at' => [
//            // Empty
//        ],
//        'email' => [
//            'mail',
//        ],
//        'bool:email_verified' => [
//            // Empty
//        ],
//         // address is a json object. Set the 'formatted' sub claim to postalAddress
//        'address' => [
//            'formatted' => ['postalAddress'],
//        ],
//        'phone_number' => [
//            'mobile',
//            'telephoneNumber',
//            'homePhone',
//        ],
//        'bool:phone_number_verified' => [
//            // Empty
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

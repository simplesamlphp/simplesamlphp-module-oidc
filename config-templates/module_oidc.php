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
];

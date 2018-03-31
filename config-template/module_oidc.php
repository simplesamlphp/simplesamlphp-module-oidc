<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
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
    // Enable PKCE (RFC7636)
    'pkce' => false,

    // Tag to run storage cleanup script using the cron module...
    'cron_tag' => 'hourly',

    // this is the auth source used for authentication,
    'auth' => 'default-sp',
    // useridattr is the attribute-name that contains the userid as returned from idp
    'useridattr' => 'uid',

    // You can create as many scopes as you want and assign attributes to them
    'scopes' => [
        'basic' => [
            'description' => 'basic scope',
        ],
        'openid' => [
            'description' => 'openId scope',
        ],
        'profile' => [
            'description' => 'profile claims',
            'attributes' => ['name', 'family_name', 'given_name', ''],
        ],
        'email' => [
            'description' => 'email and email_verified claims',
        ],
        'address' => [
            'description' => 'address claim',
        ],
        'phone' => [
            'description' => 'phone_number and phone_number_verified claims',
        ],
        'private' => [
            'description' => 'private claims',
            'private' => true, // default is false
        ],
    ],

    // Namespace
    'namespace' => false,
];

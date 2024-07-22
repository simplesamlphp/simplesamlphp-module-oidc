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

use SimpleSAML\Module\oidc\ModuleConfig;

$config = [
    ModuleConfig::OPTION_TOKEN_AUTHORIZATION_CODE_TTL => 'PT10M',
    ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL => 'P1M',
    ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_TTL => 'PT1H',

    ModuleConfig::OPTION_TOKEN_SIGNER => \Lcobucci\JWT\Signer\Rsa\Sha256::class,

    ModuleConfig::OPTION_AUTH_SOURCE => 'example-userpass',

    ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE => 'uid',
    ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
        'attribute' => 'eduPersonEntitlement',
        'client' => ['urn:example:oidc:manage:client'],
    ],

    ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS => [
        // For conformance tests we always have an authproc run just to confirm nothing is broken
        // with the integration to ProcessingChain
        5 => [
            'class' => 'core:AttributeAdd',
            'someUnusedAttribute' => 'Some value',
        ]
    ],

    // Use the below auth processing config to test authprocs with a redirect
/*    ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS => [
        5 => [
            'class' => 'core:AttributeAdd',
            '%replace',
            'givenName' => 'First AuthProc',
        ],
        10 => [
            'class' => 'preprodwarning:Warning',
        ],
        15 => [
            'class' => 'core:AttributeAdd',
            '%replace',
            'sn' => 'SN AuthProc',
        ]
    ],*/

    ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES => [
    ],
    ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE => [
        'middle_name' => [
            'middle_name'
        ],
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
        'updated_at' => [
            'type' => 'int',
            'updated_at'
        ],
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
        'phone_number_verified' => [
            'type' => 'bool',
            'phone_number_verified'
        ],
    ],

    ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED => [
        '1',
        '0',
    ],

    ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP => [
        'example-userpass' => ['1', '0'],
    ],

    ModuleConfig::OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION => null,

    ModuleConfig::OPTION_CRON_TAG => 'hourly',
];

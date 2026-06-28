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

    // Exercise the Defuse\Crypto\Key encryption key path during conformance
    // testing. Generated with `vendor/bin/generate-defuse-key`.
    ModuleConfig::OPTION_ENCRYPTION_KEY =>
        'def000009b5323e0e424b49f9d84ac93ce9cf22228bba26cc6c7bd3d12663df9b12fc69f7041b44f77ec7e14a98c8832cd7e2a6c72923a8babfde0df554e644afff6b94b',

    ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS => [
        [
            ModuleConfig::KEY_ALGORITHM => \SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum::RS256,
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME,
            ModuleConfig::KEY_PUBLIC_KEY_FILENAME => ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME,
//            ModuleConfig::KEY_PRIVATE_KEY_PASSWORD => 'private-key-password', // Optional
//            ModuleConfig::KEY_KEY_ID => 'rsa-connect-signing-key-2026', // Optional
        ],
    ],

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

    ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER => \Symfony\Component\Cache\Adapter\FilesystemAdapter::class,
    ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER_ARGUMENTS => [
        // Use defaults
    ],

    ModuleConfig::OPTION_API_ENABLED => true,

    ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED => true,

    ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED => true,

    ModuleConfig::OPTION_API_TOKENS => [
        'strong-random-token-string' => [
            \SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum::All, // Gives access to the whole API.
        ],
    ],

    // OpenID Connect Dynamic Client Registration (DCR). Enabled here so the
    // OpenID conformance "dynamic" certification test plan can register clients
    // against this OP. Open registration (no Initial Access Token) is used,
    // matching what the official dynamic certification profile exercises.
    ModuleConfig::OPTION_DCR_ENABLED => true,
    ModuleConfig::OPTION_DCR_REGISTRATION_AUTH =>
        \SimpleSAML\Module\oidc\Codebooks\DcrRegistrationAuthEnum::Open->value,
    // The conformance suite registers logo_uri/policy_uri/tos_uri on hosts that
    // intentionally differ from the redirect_uris (e.g. tos_uri=https://openid.net),
    // so impersonation protection must be off for the dynamic cert plan. The
    // module default remains enabled (secure) for normal deployments.
    ModuleConfig::OPTION_DCR_IMPERSONATION_PROTECTION_ENABLED => false,

    // Advertise 'claims_supported' in discovery metadata (RECOMMENDED by OpenID
    // Connect Discovery and checked by the dynamic certification profile). The
    // module default is false; enabled here for conformance.
    ModuleConfig::OPTION_PROTOCOL_DISCOVERY_SHOW_CLAIMS_SUPPORTED => true,

    // The conformance suite serves client jwks_uri / request_uri over a per-instance
    // self-signed TLS certificate (CN=localhost) that the OP would otherwise reject.
    // Disable TLS verification for the openid library's protocol-layer HTTP fetches so
    // those tests can run. NEVER do this in production.
    ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS => [
        'verify' => false,
    ],
];

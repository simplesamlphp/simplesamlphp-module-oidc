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
use Lcobucci\JWT\Signer\Rsa\Sha256;
use SimpleSAML\Module\oidc\ModuleConfig;

$config = [
    ModuleConfig::OPTION_ISSUER => 'http://test.issuer',

    ModuleConfig::OPTION_TOKEN_AUTHORIZATION_CODE_TTL => 'PT10M',
    ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL => 'P1M',
    ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_TTL => 'PT1H',

    ModuleConfig::OPTION_TOKEN_SIGNER => Sha256::class,

    ModuleConfig::OPTION_AUTH_SOURCE => 'default-sp',

    ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE => 'uid',

    ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES => [
    ],
    ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE => [
    ],

    ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED => [
    ],

    ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP => [
    ],

    ModuleConfig::OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION => null,

    ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS => [
    ],

    ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER => \Symfony\Component\Cache\Adapter\ArrayAdapter::class,
    ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER_ARGUMENTS => [],
    ModuleConfig::OPTION_PROTOCOL_USER_ENTITY_CACHE_DURATION => null,
    ModuleConfig::OPTION_PROTOCOL_CLIENT_ENTITY_CACHE_DURATION => 'PT10M',

    ModuleConfig::OPTION_CRON_TAG => 'hourly',

    ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
        'attribute' => 'eduPersonEntitlement',
        'client' => ['urn:example:oidc:manage:client'],
    ],

    ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE => 20,

    ModuleConfig::OPTION_FEDERATION_ENABLED => false,

    ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS => [
        // phpcs:ignore
        'https://ta.example.org/' => '{"keys":[{"kty": "RSA","alg": "RS256","use": "sig","kid": "Nzb...9Xs","e": "AQAB","n": "pnXB...ub9J"}]}',
        'https://ta2.example.org/' => null,
    ],

    ModuleConfig::OPTION_FEDERATION_AUTHORITY_HINTS => [
        'https://intermediate.example.org/',
    ],

    ModuleConfig::OPTION_FEDERATION_TRUST_MARK_TOKENS => [
        'eyJ...GHg',
    ],

    ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS => [
        // We are limiting federation participation using Trust Marks for 'https://ta.example.org/'.
        'https://ta.example.org/' => [
            // Entities must have (at least) one Trust Mark from the list below.
            \SimpleSAML\Module\oidc\Codebooks\LimitsEnum::OneOf->value => [
                'trust-mark-type',
                'trust-mark-type-2',
            ],
            // Entities must have all Trust Marks from the list below.
            \SimpleSAML\Module\oidc\Codebooks\LimitsEnum::AllOf->value => [
                'trust-mark-type-3',
                'trust-mark-type-4',
            ],
        ],
    ],

    ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER => \Symfony\Component\Cache\Adapter\ArrayAdapter::class,
    ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER_ARGUMENTS => [],
    ModuleConfig::OPTION_FEDERATION_ENTITY_STATEMENT_DURATION => 'P1D',
    ModuleConfig::OPTION_FEDERATION_CACHE_DURATION_FOR_PRODUCED => 'PT2M',

    ModuleConfig::OPTION_FEDERATION_CACHE_MAX_DURATION_FOR_FETCHED => 'PT6H',

    ModuleConfig::OPTION_PKI_FEDERATION_PRIVATE_KEY_FILENAME =>
        ModuleConfig::DEFAULT_PKI_FEDERATION_PRIVATE_KEY_FILENAME,
    ModuleConfig::OPTION_PKI_FEDERATION_PRIVATE_KEY_PASSPHRASE => 'abc123',
    ModuleConfig::OPTION_PKI_FEDERATION_CERTIFICATE_FILENAME =>
        ModuleConfig::DEFAULT_PKI_FEDERATION_CERTIFICATE_FILENAME,

    ModuleConfig::OPTION_FEDERATION_TOKEN_SIGNER => Sha256::class,

    ModuleConfig::OPTION_ORGANIZATION_NAME => 'Foo corp',
    ModuleConfig::OPTION_DISPLAY_NAME => 'Foo corp',
    ModuleConfig::OPTION_DESCRIPTION => 'Foo provider',
    ModuleConfig::OPTION_KEYWORDS => ['openid', 'oidc', 'op', 'federation'],
    ModuleConfig::OPTION_CONTACTS => [
        'John Doe jdoe@example.org',
    ],
    ModuleConfig::OPTION_LOGO_URI => 'https://example.org/logo',
    ModuleConfig::OPTION_POLICY_URI => 'https://example.org/policy',
    ModuleConfig::OPTION_INFORMATION_URI => 'https://example.org/info',
    ModuleConfig::OPTION_HOMEPAGE_URI => 'https://example.org',
    ModuleConfig::OPTION_ORGANIZATION_URI => 'https://example.org',
];

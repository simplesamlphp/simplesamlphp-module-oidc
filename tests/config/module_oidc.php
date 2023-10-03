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
    ModuleConfig::OPTION_TOKEN_AUTHORIZATION_CODE_TTL => 'PT10M',
    ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL => 'P1M',
    ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_TTL => 'PT1H',

    ModuleConfig::OPTION_CRON_TAG => 'hourly',

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
];

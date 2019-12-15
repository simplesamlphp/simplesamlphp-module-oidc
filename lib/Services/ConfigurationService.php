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

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module;
use SimpleSAML\Utils\HTTP;

class ConfigurationService
{
    protected static $standardClaims = [
        'openid' => [
            'description' => 'openid',
        ],
        'profile' => [
            'description' => 'profile',
        ],
        'email' => [
            'description' => 'email',
        ],
        'address' => [
            'description' => 'address',
        ],
        'phone' => [
            'description' => 'phone',
        ],
    ];

    public function __construct()
    {
        $this->validateConfiguration();
    }

    public function getSimpleSAMLConfiguration(): Configuration
    {
        return Configuration::getInstance();
    }

    public function getOpenIDConnectConfiguration(): Configuration
    {
        return Configuration::getConfig('module_oidc.php');
    }

    public function getSimpleSAMLSelfURLHost()
    {
        return HTTP::getSelfURLHost();
    }

    public function getOpenIdConnectModuleURL(string $path = null): string
    {
        $base = Module::getModuleURL('oidc');

        if ($path) {
            $base .= "/{$path}";
        }

        return $base;
    }

    public function getOpenIDScopes()
    {
        $scopes = $this->getOpenIDConnectConfiguration()->getArray('scopes', []);

        return array_merge(self::$standardClaims, $scopes);
    }

    public function getOpenIDPrivateScopes()
    {
        return $this->getOpenIDConnectConfiguration()->getArray('scopes', []);
    }

    private function validateConfiguration()
    {
        $scopes = $this->getOpenIDConnectConfiguration()->getArray('scopes', []);
        array_walk($scopes, function ($scope, $name) {
            if (\in_array($name, ['openid', 'profile', 'email', 'address', 'phone'], true)) {
                throw new ConfigurationError('Protected scope can be overwrited: '.$name, 'oidc_config.php');
            }
            if (!\array_key_exists('description', $scope)) {
                throw new ConfigurationError('Scope ['.$name.'] description not defined', 'module_oidc.php');
            }
        });
    }
}

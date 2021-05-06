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

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use PhpParser\Node\Scalar\String_;
use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module;
use SimpleSAML\Modules\OpenIDConnect\Utils\FingerprintGenerator;
use SimpleSAML\Utils\Config;
use SimpleSAML\Utils\HTTP;

class ConfigurationService
{
    /** @var array */
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

    /**
     * @return string
     */
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

    /**
     * @return array
     */
    public function getOpenIDScopes()
    {
        $scopes = $this->getOpenIDConnectConfiguration()->getArray('scopes', []);

        return array_merge(self::$standardClaims, $scopes);
    }

    /**
     * @return array
     */
    public function getOpenIDPrivateScopes()
    {
        return $this->getOpenIDConnectConfiguration()->getArray('scopes', []);
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     *
     * @return void
     */
    private function validateConfiguration()
    {
        $scopes = $this->getOpenIDConnectConfiguration()->getArray('scopes', []);
        array_walk(
            $scopes,
            /**
             * @param array  $scope
             * @param string $name
             *
             * @return void
             */
            function ($scope, $name) {
                if (\in_array($name, ['openid', 'profile', 'email', 'address', 'phone'], true)) {
                    throw new ConfigurationError('Protected scope can be overwrited: ' . $name, 'oidc_config.php');
                }
                if (!\array_key_exists('description', $scope)) {
                    throw new ConfigurationError('Scope [' . $name . '] description not defined', 'module_oidc.php');
                }
            }
        );
    }

    public function getSigner(): Signer
    {
        /** @psalm-var class-string $signerClassname */
        $signerClassname = (string) $this->getOpenIDConnectConfiguration()->getString('signer', Sha256::class);

        $class = new \ReflectionClass($signerClassname);
        $signer = $class->newInstance();

        if (!$signer instanceof Signer) {
            return new Sha256();
        }

        return $signer;
    }

    public function getKeyId(): String
    {
        $defaultKeyId = FingerprintGenerator::forFile(Config::getCertPath('oidc_module.crt'));
        return $this->getOpenIDConnectConfiguration()->getString('kid', $defaultKeyId);
    }

    /**
     * Get autproc filters defined in the OIDC configuration.
     *
     * @return array
     * @throws \Exception
     */
    public function getAuthProcFilters(): array
    {
        return $this->getOpenIDConnectConfiguration()->getArray('authproc.oidc', []);
    }
}

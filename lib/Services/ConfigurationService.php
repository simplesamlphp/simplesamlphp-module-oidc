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

namespace SimpleSAML\Module\oidc\Services;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use PhpParser\Node\Scalar\String_;
use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;
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

        $acrValuesSupported = $this->getAcrValuesSupported();
        foreach ($acrValuesSupported as $acrValueSupported) {
            if (! is_string($acrValueSupported)) {
                throw new ConfigurationError('Config option acrValuesSupported should contain strings only.');
            }
        }

        $authSourcesToAcrValuesMap = $this->getAuthSourcesToAcrValuesMap();
        foreach ($authSourcesToAcrValuesMap as $authSource => $acrValues) {
            if (! is_string($authSource)) {
                throw new ConfigurationError('Config option authSourcesToAcrValuesMap should have string keys ' .
                                             'indicating auth sources.');
            }

            if (! is_array($acrValues)) {
                throw new ConfigurationError('Config option authSourcesToAcrValuesMap should have array ' .
                                             'values containing supported ACRs for each auth source key.');
            }

            foreach ($acrValues as $acrValue) {
                if (! is_string($acrValue)) {
                    throw new ConfigurationError('Config option authSourcesToAcrValuesMap should have array ' .
                                                 'values with strings only.');
                }

                if (! in_array($acrValue, $acrValuesSupported)) {
                    throw new ConfigurationError('Config option authSourcesToAcrValuesMap should have ' .
                                                 'supported ACR values only.');
                }
            }
        }

        $forcedAcrValueForCookieAuthentication = $this->getForcedAcrValueForCookieAuthentication();

        if (! is_null($forcedAcrValueForCookieAuthentication)) {
            if (! in_array($forcedAcrValueForCookieAuthentication, $acrValuesSupported)) {
                throw new ConfigurationError('Config option forcedAcrValueForCookieAuthentication should have' .
                                             ' null value or string value indicating particular supported ACR.');
            }
        }
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

    /**
     * Return the path to the public certificate
     * @return string The file system path
     */
    public function getCertPath(): string
    {
        return Config::getCertPath('oidc_module.crt');
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

    /**
     * Get supported Authentication Context Class References (ACRs).
     *
     * @return array
     * @throws \Exception
     */
    public function getAcrValuesSupported(): array
    {
        return array_values($this->getOpenIDConnectConfiguration()->getArray('acrValuesSupported', []));
    }

    /**
     * Get a map of auth sources and their supported ACRs
     *
     * @return array
     * @throws \Exception
     */
    public function getAuthSourcesToAcrValuesMap(): array
    {
        return $this->getOpenIDConnectConfiguration()->getArray('authSourcesToAcrValuesMap', []);
    }

    /**
     * @return null|string
     * @throws \Exception
     */
    public function getForcedAcrValueForCookieAuthentication(): ?string
    {
        $value = $this->getOpenIDConnectConfiguration()
            ->getValue('forcedAcrValueForCookieAuthentication', null);

        if (is_null($value)) {
            return null;
        }

        return (string) $value;
    }
}

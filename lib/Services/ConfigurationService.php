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

use Exception;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use ReflectionClass;
use ReflectionException;
use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module;
use SimpleSAML\Utils\Config;
use SimpleSAML\Utils\HTTP;

class ConfigurationService
{
    protected static array $standardClaims = [
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

    /**
     * @throws ConfigurationError
     */
    public function __construct()
    {
        $this->validateConfiguration();
    }

    /**
     * @throws Exception
     */
    public function getSimpleSAMLConfiguration(): Configuration
    {
        return Configuration::getInstance();
    }

    /**
     * @throws Exception
     */
    public function getOpenIDConnectConfiguration(): Configuration
    {
        return Configuration::getConfig('module_oidc.php');
    }

    public function getSimpleSAMLSelfURLHost(): string
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
     * @throws Exception
     */
    public function getOpenIDScopes(): array
    {
        return array_merge(self::$standardClaims, $this->getOpenIDPrivateScopes());
    }

    /**
     * @throws Exception
     */
    public function getOpenIDPrivateScopes(): array
    {
        return $this->getOpenIDConnectConfiguration()->getArray('scopes', []);
    }

    /**
     * @return void
     * @throws Exception
     *
     * @throws ConfigurationError
     */
    private function validateConfiguration()
    {
        $privateScopes = $this->getOpenIDPrivateScopes();
        array_walk(
            $privateScopes,
            /**
             * @throws ConfigurationError
             */
            function (array $scope, string $name): void {
                if (in_array($name, ['openid', 'profile', 'email', 'address', 'phone'], true)) {
                    throw new ConfigurationError('Can not overwrite protected scope: ' . $name, 'oidc_config.php');
                }
                if (!array_key_exists('description', $scope)) {
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

    /**
     * @throws ReflectionException
     * @throws Exception
     */
    public function getSigner(): Signer
    {
        /** @psalm-var class-string $signerClassname */
        $signerClassname = (string) $this->getOpenIDConnectConfiguration()->getString('signer', Sha256::class);

        $class = new ReflectionClass($signerClassname);
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
        $certName = $this->getOpenIDConnectConfiguration()->getString('certificate', 'oidc_module.crt');
        return Config::getCertPath($certName);
    }

    /**
     * Get the path to the private key
     * @return string
     */
    public function getPrivateKeyPath(): string
    {
        $keyName = $this->getOpenIDConnectConfiguration()->getString('privatekey', 'oidc_module.pem');
        return Config::getCertPath($keyName);
    }

    /**
     * Get the path to the private key
     * @return ?string
     * @throws Exception
     */
    public function getPrivateKeyPassPhrase(): ?string
    {
        return $this->getOpenIDConnectConfiguration()->getString('pass_phrase', null);
    }

    /**
     * Get autproc filters defined in the OIDC configuration.
     *
     * @return array
     * @throws Exception
     */
    public function getAuthProcFilters(): array
    {
        return $this->getOpenIDConnectConfiguration()->getArray('authproc.oidc', []);
    }

    /**
     * Get supported Authentication Context Class References (ACRs).
     *
     * @return array
     * @throws Exception
     */
    public function getAcrValuesSupported(): array
    {
        return array_values($this->getOpenIDConnectConfiguration()->getArray('acrValuesSupported', []));
    }

    /**
     * Get a map of auth sources and their supported ACRs
     *
     * @return array
     * @throws Exception
     */
    public function getAuthSourcesToAcrValuesMap(): array
    {
        return $this->getOpenIDConnectConfiguration()->getArray('authSourcesToAcrValuesMap', []);
    }

    /**
     * @return null|string
     * @throws Exception
     */
    public function getForcedAcrValueForCookieAuthentication(): ?string
    {
        $value = $this->getOpenIDConnectConfiguration()
            ->getValue('forcedAcrValueForCookieAuthentication');

        if (is_null($value)) {
            return null;
        }

        return (string) $value;
    }
}

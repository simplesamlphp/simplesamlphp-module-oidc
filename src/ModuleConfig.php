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

namespace SimpleSAML\Module\oidc;

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

class ModuleConfig
{
    /**
     * Default file name for module configuration. Can be overridden in constructor, for example, for testing purposes.
     */
    final public const DEFAULT_FILE_NAME = 'module_oidc.php';

    final public const OPTION_PKI_PRIVATE_KEY_PASSPHRASE = 'pass_phrase';
    final public const OPTION_PKI_PRIVATE_KEY_FILENAME = 'privatekey';
    final public const DEFAULT_PKI_PRIVATE_KEY_FILENAME = 'oidc_module.key';
    final public const OPTION_PKI_CERTIFICATE_FILENAME = 'certificate';
    final public const DEFAULT_PKI_CERTIFICATE_FILENAME = 'oidc_module.crt';
    final public const OPTION_TOKEN_AUTHORIZATION_CODE_TTL = 'authCodeDuration';
    final public const OPTION_TOKEN_REFRESH_TOKEN_TTL = 'refreshTokenDuration';
    final public const OPTION_TOKEN_ACCESS_TOKEN_TTL = 'accessTokenDuration';
    final public const OPTION_TOKEN_SIGNER = 'signer';
    final public const OPTION_AUTH_SOURCE = 'auth';
    final public const OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE = 'useridattr';
    final public const OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE = 'translate';
    final public const OPTION_AUTH_CUSTOM_SCOPES = 'scopes';
    final public const OPTION_AUTH_ACR_VALUES_SUPPORTED = 'acrValuesSupported';
    final public const OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP = 'authSourcesToAcrValuesMap';
    final public const OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION = 'forcedAcrValueForCookieAuthentication';
    final public const OPTION_AUTH_PROCESSING_FILTERS = 'authproc.oidc';
    final public const OPTION_CRON_TAG = 'cron_tag';
    final public const OPTION_ADMIN_UI_PERMISSIONS = 'permissions';
    final public const OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE = 'items_per_page';

    protected static array $standardClaims = [
        // TODO mivanci Move registered scopes to enum?
        'openid' => [
            'description' => 'openid',
        ],
        'offline_access' => [
            'description' => 'offline_access',
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
     * @var Configuration Module configuration instance created form module config file.
     */
    private readonly Configuration $moduleConfig;
    /**
     * @var Configuration SimpleSAMLphp configuration instance.
     */
    private readonly Configuration $sspConfig;

    /**
     * @throws Exception
     */
    public function __construct(
        string $fileName = self::DEFAULT_FILE_NAME, // Primarily used for easy (unit) testing overrides.
        array $overrides = [] // Primarily used for easy (unit) testing overrides.
    ) {
        $this->moduleConfig = Configuration::loadFromArray(
            array_merge(Configuration::getConfig($fileName)->toArray(), $overrides)
        );

        $this->sspConfig = Configuration::getInstance();

        $this->validate();
    }

    /**
     * @throws Exception
     */
    public function sspConfig(): Configuration
    {
        return $this->sspConfig;
    }

    /**
     * @throws Exception
     */
    public function config(): Configuration
    {
        return $this->moduleConfig;
    }

    public function getSimpleSAMLSelfURLHost(): string
    {
        // TODO mivanci Create bridge to SSP utility classes
        return (new HTTP())->getSelfURLHost();
    }

    public function getOpenIdConnectModuleURL(string $path = null): string
    {
        // TODO mivanci Create bridge to SSP utility classes
        $base = Module::getModuleURL('oidc');

        if ($path) {
            $base .= "/$path";
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
        return $this->config()->getOptionalArray(self::OPTION_AUTH_CUSTOM_SCOPES, []);
    }

    /**
     * @return void
     * @throws Exception
     *
     * @throws ConfigurationError
     */
    private function validate(): void
    {
        $privateScopes = $this->getOpenIDPrivateScopes();
        array_walk(
            $privateScopes,
            /**
             * @throws ConfigurationError
             */
            function (array $scope, string $name): void {
                if (in_array($name, array_keys(self::$standardClaims), true)) {
                    throw new ConfigurationError(
                        'Can not overwrite protected scope: ' . $name,
                        self::DEFAULT_FILE_NAME
                    );
                }
                if (!array_key_exists('description', $scope)) {
                    throw new ConfigurationError(
                        'Scope [' . $name . '] description not defined',
                        self::DEFAULT_FILE_NAME
                    );
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

            /** @psalm-suppress MixedAssignment */
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
        $signerClassname = $this->config()->getOptionalString(
            self::OPTION_TOKEN_SIGNER,
            Sha256::class
        );

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
     * @throws Exception
     */
    public function getCertPath(): string
    {
        $certName = $this->config()->getOptionalString(
            self::OPTION_PKI_CERTIFICATE_FILENAME,
            self::DEFAULT_PKI_CERTIFICATE_FILENAME
        );
        return (new Config())->getCertPath($certName);
    }

    /**
     * Get the path to the private key
     * @throws Exception
     */
    public function getPrivateKeyPath(): string
    {
        $keyName = $this->config()->getOptionalString(
            self::OPTION_PKI_PRIVATE_KEY_FILENAME,
            self::DEFAULT_PKI_PRIVATE_KEY_FILENAME
        );
        // TODO mivanci move to bridge classes to SSP utils
        return (new Config())->getCertPath($keyName);
    }

    /**
     * Get the path to the private key
     * @return ?string
     * @throws Exception
     */
    public function getPrivateKeyPassPhrase(): ?string
    {
        return $this->config()->getOptionalString(self::OPTION_PKI_PRIVATE_KEY_PASSPHRASE, null);
    }

    /**
     * Get autproc filters defined in the OIDC configuration.
     *
     * @return array
     * @throws Exception
     */
    public function getAuthProcFilters(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_AUTH_PROCESSING_FILTERS, []);
    }

    /**
     * Get supported Authentication Context Class References (ACRs).
     *
     * @return array
     * @throws Exception
     */
    public function getAcrValuesSupported(): array
    {
        return array_values($this->config()->getOptionalArray(self::OPTION_AUTH_ACR_VALUES_SUPPORTED, []));
    }

    /**
     * Get a map of auth sources and their supported ACRs
     *
     * @return array
     * @throws Exception
     */
    public function getAuthSourcesToAcrValuesMap(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP, []);
    }

    /**
     * @return null|string
     * @throws Exception
     */
    public function getForcedAcrValueForCookieAuthentication(): ?string
    {
        /** @psalm-suppress MixedAssignment */
        $value = $this->config()
            ->getOptionalValue(self::OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION, null);

        if (is_null($value)) {
            return null;
        }

        return (string) $value;
    }
}

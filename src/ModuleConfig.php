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

use DateInterval;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use ReflectionClass;
use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\ScopesEnum;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

class ModuleConfig
{
    final public const MODULE_NAME = 'oidc';
    protected const KEY_DESCRIPTION = 'description';

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
    final public const OPTION_FEDERATION_TOKEN_SIGNER = 'federation_token_signer';
    final public const OPTION_PKI_FEDERATION_PRIVATE_KEY_PASSPHRASE = 'federation_private_key_passphrase';
    final public const OPTION_PKI_FEDERATION_PRIVATE_KEY_FILENAME = 'federation_private_key_filename';
    final public const DEFAULT_PKI_FEDERATION_PRIVATE_KEY_FILENAME = 'oidc_module_federation.key';
    final public const OPTION_PKI_FEDERATION_CERTIFICATE_FILENAME = 'federation_certificate_filename';
    final public const DEFAULT_PKI_FEDERATION_CERTIFICATE_FILENAME = 'oidc_module_federation.crt';
    final public const OPTION_ISSUER = 'issuer';
    final public const OPTION_FEDERATION_ENTITY_STATEMENT_DURATION = 'federation_entity_statement_duration';
    final public const OPTION_FEDERATION_AUTHORITY_HINTS = 'federation_authority_hints';
    final public const OPTION_ORGANIZATION_NAME = 'organization_name';
    final public const OPTION_CONTACTS = 'contacts';
    final public const OPTION_LOGO_URI = 'logo_uri';
    final public const OPTION_POLICY_URI = 'policy_uri';
    final public const OPTION_HOMEPAGE_URI = 'homepage_uri';

    protected static array $standardScopes = [
        ScopesEnum::OpenId->value => [
            self::KEY_DESCRIPTION => 'openid',
        ],
        ScopesEnum::OfflineAccess->value => [
            self::KEY_DESCRIPTION => 'offline_access',
        ],
        ScopesEnum::Profile->value => [
            self::KEY_DESCRIPTION => 'profile',
        ],
        ScopesEnum::Email->value => [
            self::KEY_DESCRIPTION => 'email',
        ],
        ScopesEnum::Address->value => [
            self::KEY_DESCRIPTION => 'address',
        ],
        ScopesEnum::Phone->value => [
            self::KEY_DESCRIPTION => 'phone',
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
     * @throws \Exception
     */
    public function __construct(
        string $fileName = self::DEFAULT_FILE_NAME, // Primarily used for easy (unit) testing overrides.
        array $overrides = [], // Primarily used for easy (unit) testing overrides.
        Configuration $sspConfig = null,
        private readonly SspBridge $sspBridge = new SspBridge(),
    ) {
        $this->moduleConfig = Configuration::loadFromArray(
            array_merge(Configuration::getConfig($fileName)->toArray(), $overrides),
        );

        $this->sspConfig = $sspConfig ?? Configuration::getInstance();

        $this->validate();
    }

    /**
     * Get SimpleSAMLphp Configuration (config.php) instance.
     */
    public function sspConfig(): Configuration
    {
        return $this->sspConfig;
    }

    /**
     * Get module config Configuration instance.
     */
    public function config(): Configuration
    {
        return $this->moduleConfig;
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @return non-empty-string
     */
    public function getIssuer(): string
    {
        $issuer = $this->config()->getOptionalString(self::OPTION_ISSUER, null) ??
        $this->sspBridge->utils()->http()->getSelfURLHost();

        if (empty($issuer)) {
            throw OidcServerException::serverError('Issuer can not be empty.');
        }
        return $issuer;
    }

    public function getModuleUrl(string $path = null): string
    {
        $base = $this->sspBridge->module()->getModuleURL(self::MODULE_NAME);

        if ($path) {
            $base .= "/$path";
        }

        return $base;
    }

    /**
     * @throws \Exception
     */
    public function getOpenIDScopes(): array
    {
        return array_merge(self::$standardScopes, $this->getOpenIDPrivateScopes());
    }

    /**
     * @throws \Exception
     */
    public function getOpenIDPrivateScopes(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_AUTH_CUSTOM_SCOPES, []);
    }

    /**
     * @return void
     * @throws \Exception
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    private function validate(): void
    {
        $privateScopes = $this->getOpenIDPrivateScopes();
        array_walk(
            $privateScopes,
            /**
             * @throws \SimpleSAML\Error\ConfigurationError
             */
            function (array $scope, string $name): void {
                if (in_array($name, array_keys(self::$standardScopes), true)) {
                    throw new ConfigurationError(
                        'Can not overwrite protected scope: ' . $name,
                        self::DEFAULT_FILE_NAME,
                    );
                }
                if (!array_key_exists('description', $scope)) {
                    throw new ConfigurationError(
                        'Scope [' . $name . '] description not defined',
                        self::DEFAULT_FILE_NAME,
                    );
                }
            },
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
     * Get signer for OIDC protocol.
     *
     * @throws \ReflectionException
     * @throws \Exception
     */
    public function getProtocolSigner(): Signer
    {
        /** @psalm-var class-string $signerClassname */
        $signerClassname = $this->config()->getOptionalString(
            self::OPTION_TOKEN_SIGNER,
            Sha256::class,
        );

        return $this->instantiateSigner($signerClassname);
    }

    /**
     * @param class-string $className
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \ReflectionException
     */
    protected function instantiateSigner(string $className): Signer
    {
        $class = new ReflectionClass($className);
        $signer = $class->newInstance();

        if (!$signer instanceof Signer) {
            throw new ConfigurationError(sprintf('Unsupported signer class provided (%s).', $className));
        }

        return $signer;
    }

    /**
     * Get the path to the public certificate used in OIDC protocol.
     * @return string The file system path
     * @throws \Exception
     */
    public function getProtocolCertPath(): string
    {
        $certName = $this->config()->getOptionalString(
            self::OPTION_PKI_CERTIFICATE_FILENAME,
            self::DEFAULT_PKI_CERTIFICATE_FILENAME,
        );
        return $this->sspBridge->utils()->config()->getCertPath($certName);
    }

    /**
     * Get the path to the private key used in OIDC protocol.
     * @throws \Exception
     */
    public function getProtocolPrivateKeyPath(): string
    {
        $keyName = $this->config()->getOptionalString(
            self::OPTION_PKI_PRIVATE_KEY_FILENAME,
            self::DEFAULT_PKI_PRIVATE_KEY_FILENAME,
        );
        return $this->sspBridge->utils()->config()->getCertPath($keyName);
    }

    /**
     * Get the OIDC protocol private key passphrase.
     * @return ?string
     * @throws \Exception
     */
    public function getProtocolPrivateKeyPassPhrase(): ?string
    {
        return $this->config()->getOptionalString(self::OPTION_PKI_PRIVATE_KEY_PASSPHRASE, null);
    }

    /**
     * Get autproc filters defined in the OIDC configuration.
     *
     * @return array
     * @throws \Exception
     */
    public function getAuthProcFilters(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_AUTH_PROCESSING_FILTERS, []);
    }

    /**
     * Get supported Authentication Context Class References (ACRs).
     *
     * @return array
     * @throws \Exception
     */
    public function getAcrValuesSupported(): array
    {
        return array_values($this->config()->getOptionalArray(self::OPTION_AUTH_ACR_VALUES_SUPPORTED, []));
    }

    /**
     * Get a map of auth sources and their supported ACRs
     *
     * @return array
     * @throws \Exception
     */
    public function getAuthSourcesToAcrValuesMap(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP, []);
    }

    /**
     * @return null|string
     * @throws \Exception
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

    /**
     * @throws \Exception
     */
    public function getUserIdentifierAttribute(): string
    {
        return $this->config()->getString(ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE);
    }

    /**
     * @throws \ReflectionException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getFederationSigner(): ?Signer
    {
        /** @psalm-var ?class-string $signerClassname */
        $signerClassname = $this->config()->getOptionalString(self::OPTION_FEDERATION_TOKEN_SIGNER, null);

        return is_null($signerClassname) ? null : $this->instantiateSigner($signerClassname);
    }

    public function getFederationPrivateKeyPath(): ?string
    {
        $keyName = $this->config()->getOptionalString(
            self::OPTION_PKI_FEDERATION_PRIVATE_KEY_FILENAME,
            null,
        );

        return is_null($keyName) ? null : $this->sspBridge->utils()->config()->getCertPath($keyName);
    }

    public function getFederationPrivateKeyPassPhrase(): ?string
    {
        return $this->config()->getOptionalString(self::OPTION_PKI_FEDERATION_PRIVATE_KEY_PASSPHRASE, null);
    }

    /**
     * Return the path to the federation public certificate
     * @return ?string The file system path or null if not set.
     * @throws \Exception
     */
    public function getFederationCertPath(): ?string
    {
        $certName = $this->config()->getOptionalString(
            self::OPTION_PKI_FEDERATION_CERTIFICATE_FILENAME,
            null,
        );

        return is_null($certName) ? null : $this->sspBridge->utils()->config()->getCertPath($certName);
    }

    /**
     * @throws \Exception
     */
    public function getFederationEntityStatementDuration(): DateInterval
    {
        return new DateInterval(
            $this->config()->getOptionalString(
                self::OPTION_FEDERATION_ENTITY_STATEMENT_DURATION,
                null,
            ) ?? 'P1D',
        );
    }

    public function getFederationAuthorityHints(): ?array
    {
        $authorityHints = $this->config()->getOptionalArray(
            self::OPTION_FEDERATION_AUTHORITY_HINTS,
            null,
        );

        return empty($authorityHints) ? null : $authorityHints;
    }

    public function getOrganizationName(): ?string
    {
        return $this->config()->getOptionalString(
            self::OPTION_ORGANIZATION_NAME,
            null,
        );
    }

    public function getContacts(): ?array
    {
        return $this->config()->getOptionalArray(
            self::OPTION_CONTACTS,
            null,
        );
    }

    public function getLogoUri(): ?string
    {
        return $this->config()->getOptionalString(
            self::OPTION_LOGO_URI,
            null,
        );
    }

    public function getPolicyUri(): ?string
    {
        return $this->config()->getOptionalString(
            self::OPTION_POLICY_URI,
            null,
        );
    }

    public function getHomepageUri(): ?string
    {
        return $this->config()->getOptionalString(
            self::OPTION_HOMEPAGE_URI,
            null,
        );
    }
}

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
use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ScopesEnum;
use SimpleSAML\OpenID\Codebooks\TrustMarkStatusEndpointUsagePolicyEnum;
use SimpleSAML\OpenID\Serializers\JwsSerializerBag;
use SimpleSAML\OpenID\Serializers\JwsSerializerEnum;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;
use SimpleSAML\OpenID\ValueAbstracts;
use SimpleSAML\OpenID\ValueAbstracts\KeyPairFilenameConfig;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfig;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfigBag;

class ModuleConfig
{
    final public const string MODULE_NAME = 'oidc';
    protected const string KEY_DESCRIPTION = 'description';
    public const string KEY_ALGORITHM = 'algorithm';
    public const string KEY_PRIVATE_KEY_FILENAME = 'private_key_filename';
    public const string KEY_PUBLIC_KEY_FILENAME = 'public_key_filename';
    public const string KEY_PRIVATE_KEY_PASSWORD = 'private_key_password';
    public const string KEY_KEY_ID = 'key_id';
    final public const string DEFAULT_FILE_NAME = 'module_oidc.php';
    final public const string OPTION_PKI_PRIVATE_KEY_PASSPHRASE = 'pass_phrase';
    final public const string DEFAULT_PKI_PRIVATE_KEY_FILENAME = 'oidc_module.key';
    final public const string DEFAULT_PKI_CERTIFICATE_FILENAME = 'oidc_module.crt';
    final public const string OPTION_TOKEN_AUTHORIZATION_CODE_TTL = 'authCodeDuration';
    final public const string OPTION_TOKEN_REFRESH_TOKEN_TTL = 'refreshTokenDuration';
    final public const string OPTION_TOKEN_ACCESS_TOKEN_TTL = 'accessTokenDuration';
    final public const string OPTION_AUTH_SOURCE = 'auth';
    final public const string OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE = 'useridattr';
    final public const string OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE = 'translate';
    final public const string OPTION_AUTH_CUSTOM_SCOPES = 'scopes';
    final public const string OPTION_AUTH_ACR_VALUES_SUPPORTED = 'acrValuesSupported';
    final public const string OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP = 'authSourcesToAcrValuesMap';
    final public const string OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION =
    'forcedAcrValueForCookieAuthentication';
    final public const string OPTION_AUTH_PROCESSING_FILTERS = 'authproc.oidc';
    final public const string OPTION_CRON_TAG = 'cron_tag';
    final public const string OPTION_ADMIN_UI_PERMISSIONS = 'permissions';
    final public const string OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE = 'items_per_page';
    final public const string DEFAULT_PKI_FEDERATION_PRIVATE_KEY_FILENAME = 'oidc_module_federation.key';
    final public const string DEFAULT_PKI_FEDERATION_CERTIFICATE_FILENAME = 'oidc_module_federation.crt';
    final public const string OPTION_ISSUER = 'issuer';
    final public const string OPTION_FEDERATION_ENTITY_STATEMENT_DURATION = 'federation_entity_statement_duration';
    final public const string OPTION_FEDERATION_AUTHORITY_HINTS = 'federation_authority_hints';
    final public const string OPTION_ORGANIZATION_NAME = 'organization_name';
    final public const string OPTION_DISPLAY_NAME = 'display_name';
    final public const string OPTION_DESCRIPTION = 'description';
    final public const string OPTION_KEYWORDS = 'keywords';
    final public const string OPTION_CONTACTS = 'contacts';
    final public const string OPTION_LOGO_URI = 'logo_uri';
    final public const string OPTION_POLICY_URI = 'policy_uri';
    final public const string OPTION_INFORMATION_URI = 'information_uri';
    final public const string OPTION_ORGANIZATION_URI = 'organization_uri';
    final public const string OPTION_FEDERATION_ENABLED = 'federation_enabled';
    final public const string OPTION_FEDERATION_CACHE_ADAPTER = 'federation_cache_adapter';
    final public const string OPTION_FEDERATION_CACHE_ADAPTER_ARGUMENTS = 'federation_cache_adapter_arguments';
    final public const string OPTION_FEDERATION_CACHE_MAX_DURATION_FOR_FETCHED =
    'federation_cache_max_duration_for_fetched';
    final public const string OPTION_FEDERATION_TRUST_ANCHORS = 'federation_trust_anchors';
    final public const string OPTION_FEDERATION_TRUST_MARK_TOKENS = 'federation_trust_mark_tokens';
    final public const string OPTION_FEDERATION_DYNAMIC_TRUST_MARKS = 'federation_dynamic_trust_mark_tokens';
    final public const string OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS =
    'federation_participation_limit_by_trust_marks';
    final public const string OPTION_FEDERATION_TRUST_MARK_STATUS_ENDPOINT_USAGE_POLICY =
    'federation_trust_mark_status_endpoint_usage_policy';
    final public const string OPTION_FEDERATION_CACHE_DURATION_FOR_PRODUCED = 'federation_cache_duration_for_produced';
    final public const string OPTION_PROTOCOL_CACHE_ADAPTER = 'protocol_cache_adapter';
    final public const string OPTION_PROTOCOL_CACHE_ADAPTER_ARGUMENTS = 'protocol_cache_adapter_arguments';
    final public const string OPTION_PROTOCOL_USER_ENTITY_CACHE_DURATION = 'protocol_user_entity_cache_duration';
    final public const string OPTION_PROTOCOL_CLIENT_ENTITY_CACHE_DURATION = 'protocol_client_entity_cache_duration';
    final public const string OPTION_PROTOCOL_DISCOVERY_SHOW_CLAIMS_SUPPORTED =
    'protocol_discover_show_claims_supported';

    final public const string OPTION_VCI_ENABLED = 'vci_enabled';
    final public const string OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED =
    'vci_credential_configurations_supported';
    final public const string OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP =
    'vci_user_attribute_to_credential_claim_path_map';
    final public const string OPTION_API_ENABLED = 'api_enabled';
    final public const string OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED =
    'api_vci_credential_offer_endpoint_enabled';
    final public const string OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED =
    'api_oauth2_token_introspection_endpoint_enabled';
    final public const string OPTION_API_TOKENS = 'api_tokens';
    final public const string OPTION_DEFAULT_USERS_EMAIL_ATTRIBUTE_NAME = 'users_email_attribute_name';
    final public const string OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP =
    'auth_sources_to_users_email_attribute_name_map';
    final public const string OPTION_VCI_ISSUER_STATE_TTL = 'vci_issuer_state_ttl';
    final public const string OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS = 'vci_allow_non_registered_clients';
    final public const string OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS =
    'vci_allowed_redirect_uri_prefixes_for_non_registered_clients';
    final public const string OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS = 'protocol_signature_key_pairs';
    final public const string OPTION_FEDERATION_SIGNATURE_KEY_PAIRS = 'federation_signature_key_pairs';
    final public const string OPTION_TIMESTAMP_VALIDATION_LEEWAY = 'timestamp_validation_leeway';
    final public const string OPTION_VCI_SIGNATURE_KEY_PAIRS = 'vci_signature_key_pairs';

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
    protected ?SignatureKeyPairBag $protocolSignatureKeyPairBag = null;
    protected ?SignatureKeyPairConfigBag $protocolSignatureKeyPairConfigBag = null;
    protected ?SignatureKeyPairBag $federationSignatureKeyPairBag = null;
    protected ?SignatureKeyPairBag $vciSignatureKeyPairBag = null;
    protected ?SignatureKeyPairConfigBag $vciSignatureKeyPairConfigBag = null;

    /**
     * @throws \Exception
     */
    public function __construct(
        string $fileName = self::DEFAULT_FILE_NAME, // Primarily used for easy (unit) testing overrides.
        array $overrides = [], // Primarily used for easy (unit) testing overrides.
        ?Configuration $sspConfig = null,
        protected readonly SspBridge $sspBridge = new SspBridge(),
        protected readonly ValueAbstracts $valueAbstracts = new ValueAbstracts(),
    ) {
        $this->moduleConfig = Configuration::loadFromArray(
            array_merge(Configuration::getConfig($fileName)->toArray(), $overrides),
        );

        $this->sspConfig = $sspConfig ?? Configuration::getInstance();

        $this->validate();
    }

    /**
     * @return void
     * @throws \Exception
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    private function validate(): void
    {
        $privateScopes = $this->getPrivateScopes();
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
            if (!is_string($acrValueSupported)) {
                throw new ConfigurationError('Config option acrValuesSupported should contain strings only.');
            }
        }

        $authSourcesToAcrValuesMap = $this->getAuthSourcesToAcrValuesMap();
        foreach ($authSourcesToAcrValuesMap as $authSource => $acrValues) {
            if (!is_string($authSource)) {
                throw new ConfigurationError('Config option authSourcesToAcrValuesMap should have string keys ' .
                    'indicating auth sources.');
            }

            if (!is_array($acrValues)) {
                throw new ConfigurationError('Config option authSourcesToAcrValuesMap should have array ' .
                    'values containing supported ACRs for each auth source key.');
            }

            /** @psalm-suppress MixedAssignment */
            foreach ($acrValues as $acrValue) {
                if (!is_string($acrValue)) {
                    throw new ConfigurationError('Config option authSourcesToAcrValuesMap should have array ' .
                        'values with strings only.');
                }

                if (!in_array($acrValue, $acrValuesSupported, true)) {
                    throw new ConfigurationError('Config option authSourcesToAcrValuesMap should have ' .
                        'supported ACR values only.');
                }
            }
        }

        $forcedAcrValueForCookieAuthentication = $this->getForcedAcrValueForCookieAuthentication();

        if (!is_null($forcedAcrValueForCookieAuthentication)) {
            if (!in_array($forcedAcrValueForCookieAuthentication, $acrValuesSupported, true)) {
                throw new ConfigurationError('Config option forcedAcrValueForCookieAuthentication should have' .
                    ' null value or string value indicating particular supported ACR.');
            }
        }
    }

    public function moduleName(): string
    {
        return self::MODULE_NAME;
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

    // TODO mivanci v7 Move to dedicated \SimpleSAML\Module\oidc\Utils\Routes::getModuleUrl
    public function getModuleUrl(?string $path = null): string
    {
        $base = $this->sspBridge->module()->getModuleURL(self::MODULE_NAME);

        if ($path) {
            $base .= "/$path";
        }

        return $base;
    }

    /*****************************************************************************************************************
     * OpenID Connect related config.
     ****************************************************************************************************************/

    /**
     * @return non-empty-string
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
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

    public function getAuthCodeDuration(): DateInterval
    {
        return new DateInterval(
            $this->config()->getString(self::OPTION_TOKEN_AUTHORIZATION_CODE_TTL),
        );
    }

    public function getAccessTokenDuration(): DateInterval
    {
        return new DateInterval(
            $this->config()->getString(self::OPTION_TOKEN_ACCESS_TOKEN_TTL),
        );
    }

    public function getRefreshTokenDuration(): DateInterval
    {
        return new DateInterval(
            $this->config()->getString(self::OPTION_TOKEN_REFRESH_TOKEN_TTL),
        );
    }

    /**
     * @throws \Exception
     */
    public function getDefaultAuthSourceId(): string
    {
        return $this->config()->getString(self::OPTION_AUTH_SOURCE);
    }

    /**
     * @throws \Exception
     */
    public function getUserIdentifierAttribute(): string
    {
        return $this->config()->getString(ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE);
    }

    public function getSupportedAlgorithms(): SupportedAlgorithms
    {
        return new SupportedAlgorithms(
            new SignatureAlgorithmBag(
                SignatureAlgorithmEnum::RS256,
                SignatureAlgorithmEnum::RS384,
                SignatureAlgorithmEnum::RS512,
                SignatureAlgorithmEnum::ES256,
                SignatureAlgorithmEnum::ES384,
                SignatureAlgorithmEnum::ES512,
                SignatureAlgorithmEnum::PS256,
                SignatureAlgorithmEnum::PS384,
                SignatureAlgorithmEnum::PS512,
                SignatureAlgorithmEnum::EdDSA,
            ),
        );
    }

    public function getSupportedSerializers(): SupportedSerializers
    {
        return new SupportedSerializers(
            new JwsSerializerBag(
                JwsSerializerEnum::Compact,
            ),
        );
    }

    /**
     * @throws ConfigurationError
     * @return non-empty-array
     */
    public function getProtocolSignatureKeyPairs(): array
    {
        $signatureKeyPairs = $this->config()->getArray(ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS);

        if (empty($signatureKeyPairs)) {
            throw new ConfigurationError('At least one protocol signature key-pair pair must be provided.');
        }

        return $signatureKeyPairs;
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @psalm-suppress MixedAssignment, ArgumentTypeCoercion
     */
    public function getProtocolSignatureKeyPairConfigBag(): SignatureKeyPairConfigBag
    {
        if ($this->protocolSignatureKeyPairConfigBag instanceof SignatureKeyPairConfigBag) {
            return $this->protocolSignatureKeyPairConfigBag;
        }

        return $this->protocolSignatureKeyPairConfigBag = $this->getSignatureKeyPairConfigBag(
            $this->getProtocolSignatureKeyPairs(),
        );
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @psalm-suppress MixedAssignment, ArgumentTypeCoercion
     */
    public function getProtocolSignatureKeyPairBag(): SignatureKeyPairBag
    {
        if ($this->protocolSignatureKeyPairBag instanceof SignatureKeyPairBag) {
            return $this->protocolSignatureKeyPairBag;
        }

        return $this->protocolSignatureKeyPairBag = $this->valueAbstracts
            ->signatureKeyPairBagFactory()
            ->fromConfig($this->getProtocolSignatureKeyPairConfigBag());
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

        return (string)$value;
    }

    /**
     * @throws \Exception
     */
    public function getScopes(): array
    {
        return array_merge(
            self::$standardScopes,
            $this->getPrivateScopes(),
            // Also include VCI scopes if enabled.
            $this->getVciScopes(),
        );
    }

    /**
     * @throws \Exception
     */
    public function getPrivateScopes(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_AUTH_CUSTOM_SCOPES, []);
    }

    /**
     * @return string
     */
    public function getEncryptionKey(): string
    {
        return $this->sspBridge->utils()->config()->getSecretSalt();
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

    public function getProtocolCacheAdapterClass(): ?string
    {
        return $this->config()->getOptionalString(self::OPTION_PROTOCOL_CACHE_ADAPTER, null);
    }

    public function getProtocolCacheAdapterArguments(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_PROTOCOL_CACHE_ADAPTER_ARGUMENTS, []);
    }

    /**
     * Get cache duration for user entities (user data). If not set in configuration, it will fall back to SSP session
     * duration.
     *
     * @throws \Exception
     */
    public function getProtocolUserEntityCacheDuration(): DateInterval
    {
        return new DateInterval(
            $this->config()->getOptionalString(
                self::OPTION_PROTOCOL_USER_ENTITY_CACHE_DURATION,
                null,
            ) ?? "PT{$this->sspConfig()->getInteger('session.duration')}S",
        );
    }

    /**
     * Get cache duration for client entities (user data), with given default
     *
     * @throws \Exception
     */
    public function getProtocolClientEntityCacheDuration(): DateInterval
    {
        return new DateInterval(
            $this->config()->getOptionalString(
                self::OPTION_PROTOCOL_CLIENT_ENTITY_CACHE_DURATION,
                null,
            ) ?? 'PT10M',
        );
    }

    public function getProtocolDiscoveryShowClaimsSupported(): bool
    {
        return $this->config()->getOptionalBoolean(
            self::OPTION_PROTOCOL_DISCOVERY_SHOW_CLAIMS_SUPPORTED,
            false,
        );
    }


    /*****************************************************************************************************************
     * OpenID Federation related config.
     ****************************************************************************************************************/

    public function getFederationEnabled(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_FEDERATION_ENABLED, false);
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @psalm-suppress MixedAssignment, ArgumentTypeCoercion
     */
    public function getFederationSignatureKeyPairBag(): SignatureKeyPairBag
    {
        if ($this->federationSignatureKeyPairBag instanceof SignatureKeyPairBag) {
            return $this->federationSignatureKeyPairBag;
        }

        $signatureKeyPairs = $this->config()->getArray(ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS);

        if (empty($signatureKeyPairs)) {
            throw new ConfigurationError('At least one federation signature key-pair pair should be provided.');
        }

        $signatureKeyPairConfigBag = $this->getSignatureKeyPairConfigBag($signatureKeyPairs);

        return $this->federationSignatureKeyPairBag = $this->valueAbstracts
            ->signatureKeyPairBagFactory()
            ->fromConfig($signatureKeyPairConfigBag);
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

    /**
     * @throws \Exception
     */
    public function getFederationEntityStatementCacheDurationForProduced(): DateInterval
    {
        return new DateInterval(
            $this->config()->getOptionalString(
                self::OPTION_FEDERATION_CACHE_DURATION_FOR_PRODUCED,
                null,
            ) ?? 'PT2M',
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

    public function getFederationTrustMarkTokens(): ?array
    {
        $trustMarks = $this->config()->getOptionalArray(
            self::OPTION_FEDERATION_TRUST_MARK_TOKENS,
            null,
        );

        return empty($trustMarks) ? null : $trustMarks;
    }

    public function getFederationDynamicTrustMarks(): ?array
    {
        $dynamicTrustMarks = $this->config()->getOptionalArray(
            self::OPTION_FEDERATION_DYNAMIC_TRUST_MARKS,
            null,
        );

        return empty($dynamicTrustMarks) ? null : $dynamicTrustMarks;
    }

    public function getOrganizationName(): ?string
    {
        return $this->config()->getOptionalString(
            self::OPTION_ORGANIZATION_NAME,
            null,
        );
    }

    public function getDisplayName(): ?string
    {
        return $this->config()->getOptionalString(
            self::OPTION_DISPLAY_NAME,
            null,
        );
    }

    public function getDescription(): ?string
    {
        return $this->config()->getOptionalString(
            self::OPTION_DESCRIPTION,
            null,
        );
    }

    /**
     * JSON array with one or more strings representing search keywords, tags, categories, or labels that
     * apply to this Entity.
     *
     * @return ?string[]
     */
    public function getKeywords(): ?array
    {
        $keywords = $this->config()->getOptionalArray(
            self::OPTION_KEYWORDS,
            null,
        );

        if (is_null($keywords)) {
            return null;
        }

        return array_filter($keywords, fn($keyword) => is_string($keyword));
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

    public function getInformationUri(): ?string
    {
        return $this->config()->getOptionalString(
            self::OPTION_INFORMATION_URI,
            null,
        );
    }

    public function getOrganizationUri(): ?string
    {
        return $this->config()->getOptionalString(
            self::OPTION_ORGANIZATION_URI,
            null,
        );
    }

    public function getFederationCacheAdapterClass(): ?string
    {
        return $this->config()->getOptionalString(self::OPTION_FEDERATION_CACHE_ADAPTER, null);
    }

    public function getFederationCacheAdapterArguments(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_FEDERATION_CACHE_ADAPTER_ARGUMENTS, []);
    }

    public function getFederationCacheMaxDurationForFetched(): DateInterval
    {
        return new DateInterval(
            $this->config()->getOptionalString(self::OPTION_FEDERATION_CACHE_MAX_DURATION_FOR_FETCHED, 'PT6H'),
        );
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getFederationTrustAnchors(): array
    {
        $trustAnchors = $this->config()->getOptionalArray(self::OPTION_FEDERATION_TRUST_ANCHORS, []);

        if (empty($trustAnchors) && $this->getFederationEnabled()) {
            throw new ConfigurationError('No Trust Anchors have been configured.');
        }

        return $trustAnchors;
    }

    /**
     * @return non-empty-array<array-key, non-empty-string>
     * @psalm-suppress LessSpecificReturnStatement, MoreSpecificReturnType
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getFederationTrustAnchorIds(): array
    {
        return array_map('strval', array_keys($this->getFederationTrustAnchors()));
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getTrustAnchorJwksJson(string $trustAnchorId): ?string
    {
        /** @psalm-suppress MixedAssignment */
        $jwks = $this->getFederationTrustAnchors()[$trustAnchorId] ?? null;

        if (is_null($jwks)) {
            return null;
        }

        if (is_string($jwks)) {
            return $jwks;
        }

        throw new ConfigurationError(
            sprintf('Unexpected JWKS format for Trust Anchor %s: %s', $trustAnchorId, var_export($jwks, true)),
        );
    }

    public function getFederationParticipationLimitByTrustMarks(): array
    {
        return $this->config()->getOptionalArray(
            self::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS,
            [],
        );
    }

    public function getFederationTrustMarkStatusEndpointUsagePolicy(): TrustMarkStatusEndpointUsagePolicyEnum
    {
        /** @psalm-suppress MixedAssignment */
        $policy = $this->config()->getOptionalValue(
            self::OPTION_FEDERATION_TRUST_MARK_STATUS_ENDPOINT_USAGE_POLICY,
            null,
        );

        if ($policy instanceof TrustMarkStatusEndpointUsagePolicyEnum) {
            return $policy;
        }

        return TrustMarkStatusEndpointUsagePolicyEnum::RequiredIfEndpointProvidedForNonExpiringTrustMarksOnly;
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getTrustMarksNeededForFederationParticipationFor(string $trustAnchorId): array
    {
        $participationLimit = $this->getFederationParticipationLimitByTrustMarks()[$trustAnchorId] ?? [];
        if (!is_array($participationLimit)) {
            throw new ConfigurationError('Invalid configuration for federation participation limit.');
        }

        return $participationLimit;
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function isFederationParticipationLimitedByTrustMarksFor(string $trustAnchorId): bool
    {
        return !empty($this->getTrustMarksNeededForFederationParticipationFor($trustAnchorId));
    }


    /*****************************************************************************************************************
     * OpenID Verifiable Credential Issuance related config.
     ****************************************************************************************************************/

    public function getVciEnabled(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_VCI_ENABLED, false);
    }


    /**
     * @throws ConfigurationError
     * @return non-empty-array
     */
    public function getVciSignatureKeyPairs(): array
    {

        $signatureKeyPairs = $this->config()->getArray(ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS);

        if (empty($signatureKeyPairs)) {
            throw new ConfigurationError('At least one VCI signature key-pair pair must be provided.');
        }

        return $signatureKeyPairs;
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @psalm-suppress MixedAssignment, ArgumentTypeCoercion
     */
    public function getVciSignatureKeyPairConfigBag(): SignatureKeyPairConfigBag
    {
        if ($this->vciSignatureKeyPairConfigBag instanceof SignatureKeyPairConfigBag) {
            return $this->vciSignatureKeyPairConfigBag;
        }

        return $this->vciSignatureKeyPairConfigBag = $this->getSignatureKeyPairConfigBag(
            $this->getVciSignatureKeyPairs(),
        );
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @psalm-suppress MixedAssignment, ArgumentTypeCoercion
     */
    public function getVciSignatureKeyPairBag(): SignatureKeyPairBag
    {
        if ($this->vciSignatureKeyPairBag instanceof SignatureKeyPairBag) {
            return $this->vciSignatureKeyPairBag;
        }

        return $this->vciSignatureKeyPairBag = $this->valueAbstracts
            ->signatureKeyPairBagFactory()
            ->fromConfig($this->getVciSignatureKeyPairConfigBag());
    }

    public function getVciCredentialConfigurationsSupported(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED, []);
    }

    /**
     * @param string $credentialConfigurationId
     * @return mixed[]|null
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getVciCredentialConfiguration(string $credentialConfigurationId): ?array
    {
        $credentialConfiguration = $this->getVciCredentialConfigurationsSupported()[$credentialConfigurationId] ?? null;

        if (is_null($credentialConfiguration)) {
            return null;
        }

        if (!is_array($credentialConfiguration)) {
            throw new ConfigurationError(
                sprintf(
                    'Invalid configuration for credential configuration %s: %s',
                    $credentialConfigurationId,
                    var_export($credentialConfiguration, true),
                ),
            );
        }

        return $credentialConfiguration;
    }

    /**
     * @return array<string>
     */
    public function getVciCredentialConfigurationIdsSupported(): array
    {
        return array_map(
            'strval',
            array_keys($this->getVciCredentialConfigurationsSupported()),
        );
    }

    /**
     * Helper function to get the credential configuration IDs in a format suitable for creating ScopeEntity instances.
     * Returns an empty array if VCI is not enabled.
     *
     * @return array<string, array<string, string>>
     */
    public function getVciScopes(): array
    {
        if (!$this->getVciEnabled()) {
            return [];
        }

        $vciScopes = [];
        foreach ($this->getVciCredentialConfigurationIdsSupported() as $credentialConfigurationId) {
            $vciScopes[$credentialConfigurationId] = ['description' => $credentialConfigurationId];
        }
        return $vciScopes;
    }

    public function getVciCredentialConfigurationIdForCredentialDefinitionType(array $credentialDefinitionType): ?string
    {
        foreach (
            $this->getVciCredentialConfigurationsSupported() as $credentialConfigurationId => $credentialConfiguration
        ) {
            if (!is_array($credentialConfiguration)) {
                continue;
            }

            $credentialDefinition = $credentialConfiguration[ClaimsEnum::CredentialDefinition->value] ?? null;

            if (!is_array($credentialDefinition)) {
                continue;
            }

            /** @psalm-suppress MixedAssignment */
            $configuredType = $credentialDefinition[ClaimsEnum::Type->value] ?? null;

            if ($configuredType === $credentialDefinitionType) {
                return (string)$credentialConfigurationId;
            }
        }

        return null;
    }

    /**
     * Extract and parse the claims path definition from the credential configuration supported.
     * Returns an array of valid paths for the claims.
     */
    public function getVciValidCredentialClaimPathsFor(string $credentialConfigurationId): array
    {
        $claimsConfig = $this->getVciCredentialConfigurationsSupported()[$credentialConfigurationId]
        [ClaimsEnum::Claims->value] ?? [];

        $validPaths = [];

        if (!is_array($claimsConfig)) {
            return $validPaths;
        }

        /** @psalm-suppress MixedAssignment */
        foreach ($claimsConfig as $claim) {
            if (is_array($claim)) {
                /** @psalm-suppress MixedAssignment */
                $validPaths[] = $claim[ClaimsEnum::Path->value] ?? null;
            }
        }

        return array_filter($validPaths);
    }

    public function getVciUserAttributeToCredentialClaimPathMap(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP, []);
    }

    public function getVciUserAttributeToCredentialClaimPathMapFor(string $credentialConfigurationId): array
    {
        /** @psalm-suppress MixedAssignment */
        $map = $this->getVciUserAttributeToCredentialClaimPathMap()[$credentialConfigurationId] ?? [];

        if (is_array($map)) {
            return $map;
        }

        return [];
    }

    /**
     * Get Issuer State Duration (TTL) if set. If not set, it will fall back to Authorization Code Duration.
     *
     * @return DateInterval
     * @throws \Exception
     */
    public function getVciIssuerStateDuration(): DateInterval
    {
        $issuerStateDuration = $this->config()->getOptionalString(self::OPTION_VCI_ISSUER_STATE_TTL, null);

        if (is_null($issuerStateDuration)) {
            return $this->getAuthCodeDuration();
        }

        return new DateInterval(
            $this->config()->getString(self::OPTION_VCI_ISSUER_STATE_TTL),
        );
    }

    public function getVciAllowNonRegisteredClients(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS, false);
    }

    public function getVciAllowedRedirectUriPrefixesForNonRegisteredClients(): array
    {
        return $this->config()->getOptionalArray(
            self::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS,
            ['openid-credential-offer://',],
        );
    }


    /*****************************************************************************************************************
     * API-related config.
     ****************************************************************************************************************/

    public function getApiEnabled(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_API_ENABLED, false);
    }

    public function getApiVciCredentialOfferEndpointEnabled(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED, false);
    }

    public function getApiOAuth2TokenIntrospectionEndpointEnabled(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED, false);
    }

    /**
     * @return mixed[]|null
     */
    public function getApiTokens(): ?array
    {
        return $this->config()->getOptionalArray(self::OPTION_API_TOKENS, null);
    }

    /**
     * @param string $token
     * @return mixed[]
     */
    public function getApiTokenScopes(string $token): ?array
    {
        /** @psalm-suppress MixedAssignment */
        $tokenScopes = $this->getApiTokens()[$token] ?? null;

        if (is_array($tokenScopes)) {
            return $tokenScopes;
        }

        return null;
    }

    public function getAuthSourcesToUsersEmailAttributeMap(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP, []);
    }

    public function getUsersEmailAttributeNameForAuthSourceId(string $authSource): string
    {
        /** @psalm-suppress MixedAssignment */
        $attributeName = $this->getAuthSourcesToUsersEmailAttributeMap()[$authSource] ?? null;

        if (is_string($attributeName)) {
            return $attributeName;
        }

        return $this->getDefaultUsersEmailAttributeName();
    }

    public function getDefaultUsersEmailAttributeName(): string
    {
        return $this->config()->getOptionalString(self::OPTION_DEFAULT_USERS_EMAIL_ATTRIBUTE_NAME, 'mail');
    }

    /**
     * @return array{
     *     algorithm: \SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum,
     *     private_key_filename: non-empty-string,
     *     public_key_filename: non-empty-string,
     *     private_key_password: ?non-empty-string,
     *     key_id: ?non-empty-string
     * }
     * @throws ConfigurationError     *
     */
    public function getValidatedSignatureKeyPairArray(mixed $signatureKeyPair): array
    {
        if (!is_array($signatureKeyPair)) {
            throw new ConfigurationError(
                'Invalid value for signature key pair. Expected array, got "' .
                var_export($signatureKeyPair, true) . '".',
            );
        }

        $algorithm = $signatureKeyPair[self::KEY_ALGORITHM] ?? null;
        if (!$algorithm instanceof SignatureAlgorithmEnum) {
            throw new ConfigurationError(
                'Invalid protocol signature algorithm encountered. Expected instance of ' .
                SignatureAlgorithmEnum::class,
            );
        }

        $privateKeyFilename = $signatureKeyPair[self::KEY_PRIVATE_KEY_FILENAME] ?? null;
        if ((!is_string($privateKeyFilename)) || $privateKeyFilename === '') {
            throw new ConfigurationError(
                sprintf(
                    'Unexpected value for private key filename. Expected a non-empty string, got "%s".',
                    var_export($privateKeyFilename, true),
                ),
            );
        }
        $privateKeyFilename = $this->sspBridge->utils()->config()->getCertPath($privateKeyFilename);
        if (!file_exists($privateKeyFilename)) {
            throw new ConfigurationError(
                sprintf(
                    'Private key file does not exist: %s',
                    $privateKeyFilename,
                ),
            );
        }
        /** @var non-empty-string $privateKeyFilename */

        $publicKeyFilename = $signatureKeyPair[self::KEY_PUBLIC_KEY_FILENAME] ?? null;
        if ((!is_string($publicKeyFilename)) || $publicKeyFilename === '') {
            throw new ConfigurationError(
                sprintf(
                    'Unexpected value for public key filename. Expected a non-empty string, got "%s".',
                    var_export($publicKeyFilename, true),
                ),
            );
        }
        $publicKeyFilename = $this->sspBridge->utils()->config()->getCertPath($publicKeyFilename);
        if (!file_exists($publicKeyFilename)) {
            throw new ConfigurationError(
                sprintf(
                    'Public key file does not exist: %s',
                    $publicKeyFilename,
                ),
            );
        }
        /** @var non-empty-string $publicKeyFilename */

        $privateKeyPassword = $signatureKeyPair[self::KEY_PRIVATE_KEY_PASSWORD] ?? null;
        if (
            ((!is_string($privateKeyPassword)) && (!is_null($privateKeyPassword))) ||
            $privateKeyPassword === ''
        ) {
            throw new ConfigurationError(
                sprintf(
                    'Unexpected value for private key password. Expected a non-empty string or null, got "%s".',
                    var_export($privateKeyPassword, true),
                ),
            );
        }

        $keyId = $signatureKeyPair[self::KEY_KEY_ID] ?? null;
        if (
            ((!is_string($keyId)) && (!is_null($keyId))) ||
            $keyId === ''
        ) {
            throw new ConfigurationError(
                sprintf(
                    'Unexpected value for key ID signature key pair. Expected a non-empty string or null, got "%s".',
                    var_export($keyId, true),
                ),
            );
        }


        return [
            self::KEY_ALGORITHM => $algorithm,
            self::KEY_PRIVATE_KEY_FILENAME => $privateKeyFilename,
            self::KEY_PUBLIC_KEY_FILENAME => $publicKeyFilename,
            self::KEY_PRIVATE_KEY_PASSWORD => $privateKeyPassword,
            self::KEY_KEY_ID => $keyId,
        ];
    }

    /**
     * @throws ConfigurationError
     * @psalm-suppress MixedAssignment
     */
    protected function getSignatureKeyPairConfigBag(array $signatureKeyPairs): SignatureKeyPairConfigBag
    {
        $signatureKeyPairConfigBag = new SignatureKeyPairConfigBag();

        foreach ($signatureKeyPairs as $signatureKeyPair) {
            /**
             * @var SignatureAlgorithmEnum $algorithm
             * @var non-empty-string $privateKeyFilename
             * @var non-empty-string $publicKeyFilename
             * @var ?non-empty-string $privateKeyPassword
             * @var ?non-empty-string $keyId
             */
            [
                self::KEY_ALGORITHM => $algorithm,
                self::KEY_PRIVATE_KEY_FILENAME => $privateKeyFilename,
                self::KEY_PUBLIC_KEY_FILENAME => $publicKeyFilename,
                self::KEY_PRIVATE_KEY_PASSWORD => $privateKeyPassword,
                self::KEY_KEY_ID => $keyId,
            ] = $this->getValidatedSignatureKeyPairArray($signatureKeyPair);

            $signatureKeyPairConfigBag->add(new SignatureKeyPairConfig(
                $algorithm,
                new KeyPairFilenameConfig(
                    $privateKeyFilename,
                    $publicKeyFilename,
                    $privateKeyPassword,
                    $keyId,
                ),
            ));
        }

        return $signatureKeyPairConfigBag;
    }

    public function getTimestampValidationLeeway(): DateInterval
    {
        return new DateInterval(
            $this->config()->getOptionalString(
                self::OPTION_TIMESTAMP_VALIDATION_LEEWAY,
                'PT1M',
            ),
        );
    }
}

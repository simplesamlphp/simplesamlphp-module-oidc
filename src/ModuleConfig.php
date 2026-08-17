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
use DateTimeImmutable;
use Defuse\Crypto\Exception\CryptoException;
use Defuse\Crypto\Key;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\DcrRegistrationAuthEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPoolBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\AddressPinningModeEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;
use SimpleSAML\OpenID\Codebooks\ResponseTypesEnum;
use SimpleSAML\OpenID\Codebooks\ScopesEnum;
use SimpleSAML\OpenID\Codebooks\TokenEndpointAuthMethodsEnum;
use SimpleSAML\OpenID\Codebooks\TrustMarkStatusEndpointUsagePolicyEnum;
use SimpleSAML\OpenID\Decorators\HttpClientDecorator;
use SimpleSAML\OpenID\Network\DestinationPolicy;
use SimpleSAML\OpenID\Serializers\JwsSerializerBag;
use SimpleSAML\OpenID\Serializers\JwsSerializerEnum;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;
use SimpleSAML\OpenID\ValueAbstracts;
use SimpleSAML\OpenID\ValueAbstracts\KeyPairFilenameConfig;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfig;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfigBag;
use Throwable;

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

    /**
     * SimpleSAMLphp\Database method performing a read which is guaranteed to hit the primary rather
     * than a possibly lagging secondary. Required by the Token Status List capability.
     */
    final public const string SSP_PRIMARY_READ_METHOD = 'readPrimary';

    /**
     * Shortest Status List retirement grace which still does its job.
     *
     * See getVciStatusListRetirementGrace(): the wait has to outlast a credential issuance which was
     * already in flight, and nothing here can serialise the two instead.
     */
    final public const int MINIMUM_STATUS_LIST_RETIREMENT_GRACE_SECONDS = 3600;

    final public const string OPTION_PKI_PRIVATE_KEY_PASSPHRASE = 'pass_phrase';
    final public const string DEFAULT_PKI_PRIVATE_KEY_FILENAME = 'oidc_module.key';
    final public const string DEFAULT_PKI_CERTIFICATE_FILENAME = 'oidc_module.crt';
    final public const string OPTION_TOKEN_AUTHORIZATION_CODE_TTL = 'authCodeDuration';
    final public const string OPTION_TOKEN_REFRESH_TOKEN_TTL = 'refreshTokenDuration';
    final public const string OPTION_TOKEN_ACCESS_TOKEN_TTL = 'accessTokenDuration';
    final public const string OPTION_ENCRYPTION_KEY = 'encryption_key';
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
    final public const string OPTION_FEDERATION_HTTP_CLIENT_OPTIONS = 'federation_http_client_options';
    final public const string OPTION_FEDERATION_MAX_TRUST_CHAIN_DEPTH = 'federation_max_trust_chain_depth';
    final public const string OPTION_FEDERATION_MAX_AUTHORITY_HINTS = 'federation_max_authority_hints';
    final public const string OPTION_FEDERATION_MAX_TRUST_CHAIN_FETCHES = 'federation_max_trust_chain_fetches';
    final public const string OPTION_FEDERATION_TRUST_CHAIN_RESOLVE_TIMEOUT =
    'federation_trust_chain_resolve_timeout';
    final public const string OPTION_FEDERATION_MAX_FETCH_SIZE_BYTES = 'federation_max_fetch_size_bytes';
    final public const string OPTION_PROTOCOL_CACHE_ADAPTER = 'protocol_cache_adapter';
    final public const string OPTION_PROTOCOL_CACHE_ADAPTER_ARGUMENTS = 'protocol_cache_adapter_arguments';
    final public const string OPTION_PROTOCOL_USER_ENTITY_CACHE_DURATION = 'protocol_user_entity_cache_duration';
    final public const string OPTION_PROTOCOL_CLIENT_ENTITY_CACHE_DURATION = 'protocol_client_entity_cache_duration';
    final public const string OPTION_PROTOCOL_DISCOVERY_SHOW_CLAIMS_SUPPORTED =
    'protocol_discover_show_claims_supported';
    final public const string OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS = 'protocol_http_client_options';
    final public const string OPTION_BACKCHANNEL_LOGOUT_HTTP_CLIENT_OPTIONS =
    'backchannel_logout_http_client_options';

    final public const string OPTION_VCI_ENABLED = 'vci_enabled';
    final public const string OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED =
    'vci_credential_configurations_supported';
    final public const string OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP =
    'vci_user_attribute_to_credential_claim_path_map';
    final public const string OPTION_API_ENABLED = 'api_enabled';
    final public const string OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED =
    'api_vci_credential_offer_endpoint_enabled';
    final public const string OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED =
    'api_vci_credential_status_endpoint_enabled';
    final public const string OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED =
    'api_oauth2_token_introspection_endpoint_enabled';
    final public const string OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RESOURCE_SERVER_CLIENT_IDS =
    'api_oauth2_token_introspection_resource_server_client_ids';
    final public const string OPTION_API_TOKENS = 'api_tokens';

    /** Optional key naming an API token, so that an audit trail can say who made a change. */
    final public const string KEY_API_TOKEN_NAME = 'name';

    /** Optional key holding an API token's scopes, when the token is given a name as well. */
    final public const string KEY_API_TOKEN_SCOPES = 'scopes';

    /**
     * Longest name an API token may be given, matching the audit trail's actor column.
     *
     * @see \SimpleSAML\Module\oidc\Repositories\StatusAuditRepository
     */
    final public const int MAX_API_TOKEN_NAME_LENGTH = 191;

    final public const string OPTION_DEFAULT_USERS_EMAIL_ATTRIBUTE_NAME = 'users_email_attribute_name';
    final public const string OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP =
    'auth_sources_to_users_email_attribute_name_map';
    final public const string OPTION_VCI_ISSUER_STATE_TTL = 'vci_issuer_state_ttl';
    final public const string OPTION_VCI_NONCE_TTL = 'vci_nonce_ttl';
    final public const string OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS = 'vci_allow_non_registered_clients';
    final public const string OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS =
    'vci_allowed_redirect_uri_prefixes_for_non_registered_clients';
    final public const string OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS = 'protocol_signature_key_pairs';
    final public const string OPTION_FEDERATION_SIGNATURE_KEY_PAIRS = 'federation_signature_key_pairs';
    final public const string OPTION_TIMESTAMP_VALIDATION_LEEWAY = 'timestamp_validation_leeway';
    final public const string OPTION_VCI_SIGNATURE_KEY_PAIRS = 'vci_signature_key_pairs';
    final public const string OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT = 'vci_credential_json_ld_context';
    final public const string OPTION_VCI_STATUS_LIST_ENABLED = 'vci_status_list_enabled';
    final public const string OPTION_VCI_STATUS_LIST_KEY_PROFILE = 'vci_status_list_key_profile';
    final public const string OPTION_VCI_STATUS_LIST_POOLS = 'vci_status_list_pools';
    final public const string OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE = 'vci_status_list_requests_per_minute';
    final public const string OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE = 'vci_status_list_retirement_grace';
    final public const string OPTION_VCI_STATUS_LIST_AUDIT_RETENTION = 'vci_status_list_audit_retention';
    final public const string OPTION_VCI_CREDENTIAL_TTLS = 'vci_credential_ttls';
    final public const string OPTION_DCR_ENABLED = 'dcr_enabled';
    final public const string OPTION_DCR_REGISTRATION_AUTH = 'dcr_registration_auth';
    final public const string OPTION_DCR_INITIAL_ACCESS_TOKENS = 'dcr_initial_access_tokens';
    final public const string OPTION_DCR_IMPERSONATION_PROTECTION_ENABLED =
    'dcr_impersonation_protection_enabled';
    final public const string OPTION_DCR_DEFAULT_SCOPES = 'dcr_default_scopes';
    final public const string OPTION_DCR_REGISTERED_CLIENTS_ENABLED = 'dcr_registered_clients_enabled';
    final public const string OPTION_PAR_REQUEST_URI_TTL = 'par_request_uri_ttl';
    final public const string OPTION_REQUIRE_PUSHED_AUTHORIZATION_REQUESTS = 'require_pushed_authorization_requests';
    final public const string OPTION_REQUIRE_SIGNED_REQUEST_OBJECT = 'require_signed_request_object';
    final public const string OPTION_REQUEST_URI_PARAMETER_SUPPORTED = 'request_uri_parameter_supported';
    final public const string OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES =
    'federation_request_uri_allowed_prefixes';
    final public const string OPTION_REQUEST_URI_FETCH_TIMEOUT = 'request_uri_fetch_timeout';
    final public const string OPTION_REQUEST_URI_MAX_SIZE_BYTES = 'request_uri_max_size_bytes';

    final public const string OPTION_OUTBOUND_ALLOWED_SCHEMES = 'outbound_allowed_schemes';
    final public const string OPTION_OUTBOUND_ALLOWED_HOSTS = 'outbound_allowed_hosts';
    final public const string OPTION_OUTBOUND_ALLOWED_CIDRS = 'outbound_allowed_cidrs';
    final public const string OPTION_OUTBOUND_ADDRESS_PINNING_MODE = 'outbound_address_pinning_mode';

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
    protected ?StatusListPoolBag $vciStatusListPoolBag = null;

    /** @var ?array<string,\DateInterval> Credential configuration ID to how long its credentials live. */
    protected ?array $vciCredentialTtls = null;

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

    /**
     * Whether the issuer is explicitly configured. If it is not, getIssuer() derives it from the
     * current HTTP host, which means it can differ depending on how the OP is reached.
     */
    public function isIssuerConfigured(): bool
    {
        $issuer = $this->config()->getOptionalString(self::OPTION_ISSUER, null);

        return $issuer !== null && $issuer !== '';
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

    public function getParRequestUriTtl(): DateInterval
    {
        return new DateInterval(
            $this->config()->getOptionalString(self::OPTION_PAR_REQUEST_URI_TTL, 'PT10M'),
        );
    }

    public function getRequirePushedAuthorizationRequests(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_REQUIRE_PUSHED_AUTHORIZATION_REQUESTS, false);
    }

    public function getRequireSignedRequestObject(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_REQUIRE_SIGNED_REQUEST_OBJECT, false);
    }

    /**
     * Whether the OP supports passing the Request Object by reference using the https request_uri parameter
     * (JWT-Secured Authorization Request by reference / OpenID Federation Authentication Request by reference).
     * Note that this does not affect Pushed Authorization Request URIs (urn form), which are always supported.
     */
    public function getRequestUriParameterSupported(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_REQUEST_URI_PARAMETER_SUPPORTED, true);
    }

    /**
     * Allowed https request_uri prefixes for OpenID Federation candidates (clients not registered in storage,
     * or registered through OpenID Federation). For such clients the OP must fetch the Request Object before
     * it can establish trust, so this is the SSRF / DoS allowlist for that outbound fetch. Registered
     * (non-federation) clients are not affected; for them the request_uri must match their registered
     * request_uris exactly.
     *
     * Semantics:
     *  - null: explicitly allow any request_uri for federation candidates,
     *  - non-empty array: allow only request_uris starting with one of the given prefixes,
     *  - empty array (and the default, when the option is not set): deny all federation-candidate fetches.
     *
     * @return string[]|null
     */
    public function getFederationRequestUriAllowedPrefixes(): ?array
    {
        // Note: we read the raw config here (instead of getOptionalValue) so we can distinguish an explicit
        // null (allow any) from an absent option (deny by default), since SimpleSAML\Configuration treats a
        // null value the same as an absent one.
        $config = $this->config()->toArray();

        if (!array_key_exists(self::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES, $config)) {
            return [];
        }

        /** @var mixed $value */
        $value = $config[self::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES];

        if (is_null($value)) {
            return null;
        }

        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter($value, 'is_string'));
    }

    public function getRequestUriFetchTimeout(): int
    {
        return $this->config()->getOptionalInteger(self::OPTION_REQUEST_URI_FETCH_TIMEOUT, 5);
    }

    public function getRequestUriMaxSizeBytes(): int
    {
        return $this->config()->getOptionalInteger(self::OPTION_REQUEST_URI_MAX_SIZE_BYTES, 102400);
    }

    /*****************************************************************************************************************
     * Outbound destination policy (where this OP is willing to send requests).
     ****************************************************************************************************************/

    /**
     * URI schemes an outbound request may use. Defaults to the library's own default (https only).
     *
     * @return list<string>
     * @throws \Exception
     */
    public function getOutboundAllowedSchemes(): array
    {
        $schemes = $this->config()->getOptionalArray(
            self::OPTION_OUTBOUND_ALLOWED_SCHEMES,
            DestinationPolicy::DEFAULT_ALLOWED_SCHEMES,
        );

        return array_values(array_filter($schemes, 'is_string'));
    }

    /**
     * Hosts this deployment declares legitimate whatever they resolve to.
     *
     * @return list<string>
     * @throws \Exception
     */
    public function getOutboundAllowedHosts(): array
    {
        $hosts = $this->config()->getOptionalArray(self::OPTION_OUTBOUND_ALLOWED_HOSTS, []);

        return array_values(array_filter($hosts, 'is_string'));
    }

    /**
     * Address ranges permitted alongside the public ones, as CIDR.
     *
     * @return list<string>
     * @throws \Exception
     */
    public function getOutboundAllowedCidrs(): array
    {
        $cidrs = $this->config()->getOptionalArray(self::OPTION_OUTBOUND_ALLOWED_CIDRS, []);

        return array_values(array_filter($cidrs, 'is_string'));
    }

    /**
     * How strictly to insist on connecting to the address that was validated.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getOutboundAddressPinningMode(): AddressPinningModeEnum
    {
        /** @psalm-suppress MixedAssignment */
        $mode = $this->config()->getOptionalValue(
            self::OPTION_OUTBOUND_ADDRESS_PINNING_MODE,
            AddressPinningModeEnum::Preferred,
        );

        if ($mode instanceof AddressPinningModeEnum) {
            return $mode;
        }

        // Accepting the backing value as well keeps a configuration written as a plain string working, which
        // is easy to reach for when every neighbouring option in the file is a scalar.
        if (is_string($mode) && ($case = AddressPinningModeEnum::tryFrom($mode)) instanceof AddressPinningModeEnum) {
            return $case;
        }

        throw new ConfigurationError(
            sprintf(
                'Invalid value for %s. Expected a %s case or one of "%s", got "%s".',
                self::OPTION_OUTBOUND_ADDRESS_PINNING_MODE,
                AddressPinningModeEnum::class,
                implode('", "', array_column(AddressPinningModeEnum::cases(), 'value')),
                var_export($mode, true),
            ),
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
     * Get the ordered list of candidate user identifier attributes.
     *
     * The option may be configured either as a single string (legacy) or as an
     * array of prioritized attribute names. In heterogeneous IdP scenarios (e.g.
     * eduGAIN inter-federation) not every IdP releases the same identifier, so
     * the list is consulted in order and the first attribute that is actually
     * present in the released attributes is used.
     *
     * @return string[]
     * @throws \Exception
     */
    public function getUserIdentifierAttributes(): array
    {
        $value = $this->config()->getOptionalArrayizeString(
            ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE,
            ['uid'],
        );

        return array_values(array_filter($value, 'is_string'));
    }

    /**
     * Returns the primary (first) configured user ID candidate.
     * @throws \SimpleSAML\Error\ConfigurationError
     * @deprecated Use getUserIdentifierAttributes().
     */
    public function getUserIdentifierAttribute(): string
    {
        return $this->getUserIdentifierAttributes()[0]
        ?? throw new ConfigurationError('No user identifier attribute configured.');
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
     * @return string[]
     */
    public function getSupportedResponseModes(): array
    {
        return [
            ResponseModesEnum::Query->value,
            ResponseModesEnum::Fragment->value,
            ResponseModesEnum::FormPost->value,
        ];
    }

    /**
     * Response types a client may be registered to use.
     *
     * Shared by OP discovery metadata, the dynamic client registration validator,
     * and the client admin form so that the advertised, accepted, and admin-selectable
     * sets cannot drift apart.
     *
     * @return string[]
     */
    public function getSupportedResponseTypes(): array
    {
        return [
            ResponseTypesEnum::Code->value,
            ResponseTypesEnum::IdToken->value,
            ResponseTypesEnum::IdTokenToken->value,
        ];
    }

    /**
     * Grant types a client may be registered to use.
     *
     * Note: the discovery `grant_types_supported` may advertise additional grant types
     * that are not registered per client (e.g. the VCI pre-authorized_code grant);
     * that extension is applied by OpMetadataService on top of these values.
     *
     * @return string[]
     */
    public function getSupportedGrantTypes(): array
    {
        return [
            GrantTypesEnum::AuthorizationCode->value,
            GrantTypesEnum::Implicit->value,
            GrantTypesEnum::RefreshToken->value,
        ];
    }

    /**
     * Token endpoint authentication methods a client may be registered to use.
     *
     * @return string[]
     */
    public function getSupportedTokenEndpointAuthMethods(): array
    {
        return [
            TokenEndpointAuthMethodsEnum::ClientSecretBasic->value,
            TokenEndpointAuthMethodsEnum::ClientSecretPost->value,
            TokenEndpointAuthMethodsEnum::PrivateKeyJwt->value,
            TokenEndpointAuthMethodsEnum::None->value,
        ];
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
     * Get the encryption key used to encrypt / decrypt artifacts like
     * authorization codes and refresh tokens.
     *
     * By default (option not set), this returns the SimpleSAMLphp secret salt
     * as a string. The underlying League OAuth2 library then derives an
     * encryption key from it using a slow, CPU-intensive key derivation
     * function (key stretching) on every encrypt / decrypt operation.
     *
     * If the OPTION_ENCRYPTION_KEY option is set to an ASCII-safe string
     * representation of a \Defuse\Crypto\Key, that strong key is used directly,
     * which avoids the slow key derivation and is therefore faster. See the
     * config template for details on how to generate such a key.
     *
     * @return \Defuse\Crypto\Key|string
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getEncryptionKey(): Key|string
    {
        $encryptionKey = $this->config()->getOptionalString(self::OPTION_ENCRYPTION_KEY, null);

        if ($encryptionKey === null || $encryptionKey === '') {
            return $this->sspBridge->utils()->config()->getSecretSalt();
        }

        try {
            return Key::loadFromAsciiSafeString($encryptionKey);
        } catch (CryptoException $exception) {
            throw new ConfigurationError(
                sprintf(
                    'Invalid value for %s. Expected an ASCII-safe string representation of a ' .
                    '\Defuse\Crypto\Key. Error was: %s',
                    self::OPTION_ENCRYPTION_KEY,
                    $exception->getMessage(),
                ),
            );
        }
    }

    /**
     * Whether a dedicated encryption key is configured. When it is not, getEncryptionKey() falls
     * back to the SimpleSAMLphp secret salt, which is used as a password from which the actual key
     * is derived on every encrypt / decrypt operation.
     *
     * Note that this intentionally only reports whether the option is set. The key itself is a
     * secret and must never be exposed in the admin UI.
     */
    public function isEncryptionKeyConfigured(): bool
    {
        $encryptionKey = $this->config()->getOptionalString(self::OPTION_ENCRYPTION_KEY, null);

        return $encryptionKey !== null && $encryptionKey !== '';
    }

    /**
     * Get the configured SAML attribute to OIDC claim translation table.
     *
     * Note that this is only the configured part of the table. At runtime it is merged over the
     * default translation table, the user identifier attributes are prepended to the 'sub' claim,
     * and any per-scope claim name prefixes are applied.
     *
     * @see \SimpleSAML\Module\oidc\Factories\ClaimTranslatorExtractorFactory
     * @see \SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor::getTranslationTable()
     *
     * @return array
     * @throws \Exception
     */
    public function getSamlToOidcTranslateTable(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE, []);
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
     * Get cache duration for client entities (user data), with the given default
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

    /**
     * Guzzle HTTP client options for the protocol-layer outbound fetches performed by the `openid` library
     * (e.g. fetching a client's `jwks_uri` or a `request_uri`). The array is passed through verbatim to the
     * underlying Guzzle client, see https://docs.guzzlephp.org/en/stable/request-options.html
     *
     * Default is an empty array (the library's secure defaults apply, i.e. TLS verification ON). The primary
     * intended use is testing against endpoints with self-signed certificates (e.g. the OpenID conformance
     * suite) by setting `['verify' => false]`. DO NOT disable TLS verification in production.
     *
     * @return array<string,mixed>
     * @throws \Exception
     */
    public function getProtocolHttpClientOptions(): array
    {
        return $this->getHttpClientOptions(self::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS);
    }

    /**
     * Guzzle HTTP client options for the outbound Back-Channel Logout requests sent to the Relying Parties'
     * `backchannel_logout_uri` endpoints. The array is merged over the handler's own defaults (which set a
     * conservative timeout) and passed to the Guzzle client, see
     * https://docs.guzzlephp.org/en/stable/request-options.html
     *
     * Default is an empty array, meaning TLS verification is ON. The primary intended use is testing against
     * Relying Parties with self-signed certificates by setting `['verify' => false]`. DO NOT disable TLS
     * verification in production: the Logout Token is a signed JWT carrying the `sub` / `sid` claims, so an
     * unverified connection lets an active attacker collect it.
     *
     * @return array<string,mixed>
     * @throws \Exception
     */
    public function getBackChannelLogoutHttpClientOptions(): array
    {
        return $this->getHttpClientOptions(self::OPTION_BACKCHANNEL_LOGOUT_HTTP_CLIENT_OPTIONS);
    }

    /**
     * Read a Guzzle HTTP client options array from the given config option.
     *
     * @return array<string,mixed>
     * @throws \Exception
     */
    protected function getHttpClientOptions(string $option): array
    {
        $options = $this->config()->getOptionalArray($option, []);

        // Guzzle request options are keyed by string option names; normalize keys to satisfy that contract.
        $normalized = [];
        /** @var mixed $value */
        foreach ($options as $key => $value) {
            /** @psalm-suppress MixedAssignment */
            $normalized[(string)$key] = $value;
        }

        return $normalized;
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
     * Guzzle HTTP client options for the federation-layer outbound fetches performed by the `openid` library
     * (entity statements, subordinate listings, Trust Mark status). Kept separate from the protocol-layer
     * options because these fetches have a different risk profile: they run against arbitrary federation
     * entities, on a code path reachable before a Request Object signature has been verified.
     *
     * The array is merged OVER the library's hardening defaults (connect/request timeouts, and redirects
     * restricted to 3 https hops), so anything set here replaces the corresponding default. The library logs
     * a warning when a value undoes one of those defaults. Default here is an empty array, which keeps the
     * library defaults, including TLS verification. DO NOT disable TLS verification in production.
     *
     * @return array<string,mixed>
     * @throws \Exception
     */
    public function getFederationHttpClientOptions(): array
    {
        return $this->getHttpClientOptions(self::OPTION_FEDERATION_HTTP_CLIENT_OPTIONS);
    }

    /**
     * Maximum number of hops from the leaf entity up to a Trust Anchor. Mirrors the `openid` library default;
     * the library clamps it to 1..20.
     *
     * @throws \Exception
     */
    public function getFederationMaxTrustChainDepth(): int
    {
        return $this->config()->getOptionalInteger(self::OPTION_FEDERATION_MAX_TRUST_CHAIN_DEPTH, 9);
    }

    /**
     * Maximum number of `authority_hints` honoured per entity, which is the branching factor of the trust
     * chain traversal. Mirrors the `openid` library default; the library clamps it to 1..12.
     *
     * @throws \Exception
     */
    public function getFederationMaxAuthorityHints(): int
    {
        return $this->config()->getOptionalInteger(self::OPTION_FEDERATION_MAX_AUTHORITY_HINTS, 6);
    }

    /**
     * Maximum number of entity statement fetches allowed for a single trust chain resolution. This, together
     * with the resolve timeout, is what actually bounds the work an anonymous request can trigger: depth and
     * breadth limits alone multiply out. Mirrors the `openid` library default; clamped by it to 1..1000.
     *
     * @throws \Exception
     */
    public function getFederationMaxTrustChainFetches(): int
    {
        return $this->config()->getOptionalInteger(self::OPTION_FEDERATION_MAX_TRUST_CHAIN_FETCHES, 100);
    }

    /**
     * Wall-clock deadline, in seconds, for a single trust chain resolution. Mirrors the `openid` library
     * default; clamped by it to 1..300.
     *
     * @throws \Exception
     */
    public function getFederationTrustChainResolveTimeout(): int
    {
        return $this->config()->getOptionalInteger(self::OPTION_FEDERATION_TRUST_CHAIN_RESOLVE_TIMEOUT, 30);
    }

    /**
     * Maximum response body size, in bytes, read for a federation fetch. Mirrors the `openid` library default.
     *
     * @throws \Exception
     */
    public function getFederationMaxFetchSizeBytes(): int
    {
        return $this->config()->getOptionalInteger(
            self::OPTION_FEDERATION_MAX_FETCH_SIZE_BYTES,
            HttpClientDecorator::DEFAULT_MAX_FETCH_SIZE_BYTES,
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
     * Whether new credentials get a Token Status List entry allocated to them.
     *
     * Note what this switch does not do: it never stops the Status List endpoint from serving. Turning
     * it off must leave already issued credentials verifiable, so lists keep being served until they
     * are retired through their own lifecycle. Only allocation of new entries stops.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getVciStatusListEnabled(): bool
    {
        if (!$this->config()->getOptionalBoolean(self::OPTION_VCI_STATUS_LIST_ENABLED, false)) {
            return false;
        }

        // Refuse to enable rather than fall back to a replica read. Deciding whether a credential has
        // been revoked off a lagging secondary can publish a revoked credential as valid, and the host
        // SimpleSAMLphp is a development dependency here, so Composer can not enforce a floor for us:
        // this module can be installed into an older SimpleSAMLphp and nothing would object.
        if (!self::hasPrimaryDatabaseReadCapability()) {
            throw new ConfigurationError(
                sprintf(
                    'Token Status Lists are enabled ("%s"), but the installed SimpleSAMLphp does not ' .
                    'provide %s::%s(). Status List correctness depends on reading back what was just ' .
                    'written rather than a possibly lagging secondary, so this capability is required. ' .
                    'Upgrade SimpleSAMLphp to a version providing it, or disable "%s".',
                    self::OPTION_VCI_STATUS_LIST_ENABLED,
                    Database::class,
                    self::SSP_PRIMARY_READ_METHOD,
                    self::OPTION_VCI_STATUS_LIST_ENABLED,
                ),
                self::DEFAULT_FILE_NAME,
            );
        }

        return true;
    }

    /**
     * Whether the host SimpleSAMLphp can perform reads which bypass secondaries.
     *
     * Checked against the class rather than an instance, so that this stays a pure capability question
     * and config loading does not have to reach for a database connection.
     */
    public static function hasPrimaryDatabaseReadCapability(): bool
    {
        return method_exists(Database::class, self::SSP_PRIMARY_READ_METHOD);
    }

    /**
     * How many Status List requests one client may make per minute, or 0 for no limit.
     *
     * Off by default, and deliberately so. The limit can only be applied to whatever the request appears
     * to come from, which behind a reverse proxy is the proxy itself unless SimpleSAMLphp has been told
     * to trust it -- so a limit switched on by default would, in exactly that common deployment, put
     * every client in one bucket and start refusing a public endpoint that credentials in wallets depend
     * on. An operator turning this on is stating that they know which address arrives here.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getVciStatusListRequestsPerMinute(): int
    {
        $configured = $this->config()->getOptionalInteger(
            self::OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE,
            0,
        );

        if ($configured < 0) {
            throw new ConfigurationError(
                sprintf(
                    'Option "%s" can not be negative. Use 0 to apply no limit.',
                    self::OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE,
                ),
                self::DEFAULT_FILE_NAME,
            );
        }

        return $configured;
    }

    /**
     * How long a Status List is left alone before it may be retired.
     *
     * Applied twice over, to the two things which have to have settled down: a list is not looked at
     * until this long after it stopped accepting allocations, and it is not retired until this long
     * after the last credential in it expired. Both are the same waiting period because they answer the
     * same question -- has everything which might still be holding this list finished with it.
     *
     * Retiring a list makes its URI answer 404, and that URI is written into every credential which was
     * issued from it. Those credentials have all expired by then, so nothing which should verify stops
     * verifying, but a Relying Party which caches responses, or a wallet showing a credential it has not
     * noticed is expired, sees a fetch fail rather than a status come back. The wait is what keeps that
     * from happening the moment the last credential lapses.
     *
     * There is a floor under it, and this is the part which is not merely conservative. The first of the
     * two waits exists to outlast an issuance which was already under way when the list stopped
     * accepting allocations -- a request whose statement has read the list as open but has not yet
     * written the row claiming an index. Nothing available here can serialise those two: there are no
     * transactions, and the retiring statement and the allocating one write different rows, so neither
     * conflicts with the other however each is guarded. Outlasting the request is the only defence, and
     * a wait shorter than a request can take is not one. An hour is some two orders of magnitude beyond
     * PHP's default execution limit, and still a small fraction of the default wait.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getVciStatusListRetirementGrace(): DateInterval
    {
        $grace = $this->resolveDurationOption(
            self::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
            $this->config()->getOptionalValue(self::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE, 'P30D'),
        ) ?? new DateInterval('P30D');

        $epoch = new DateTimeImmutable('@0');

        if ($epoch->add($grace)->getTimestamp() < self::MINIMUM_STATUS_LIST_RETIREMENT_GRACE_SECONDS) {
            throw new ConfigurationError(
                sprintf(
                    'Option "%s" must be at least one hour. It is what a Status List which stopped ' .
                    'accepting credentials waits before it may be retired, and its job is to outlast a ' .
                    'credential issuance which was already under way at that moment. A shorter wait can ' .
                    'let such an issuance produce a credential naming a list which has since been ' .
                    'retired, and that credential can never be verified.',
                    self::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
                ),
                self::DEFAULT_FILE_NAME,
            );
        }

        return $grace;
    }

    /**
     * How long rows in the status audit trail are kept, or null to keep them indefinitely.
     *
     * No default, deliberately. What an audit trail is for is answering questions later, and how much
     * later is a matter of the deployment's own obligations rather than something this module can guess
     * -- so nothing is discarded unless an operator says how long is long enough. The trail is small
     * (one row per status change, never one per credential), so keeping it costs little.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getVciStatusListAuditRetention(): ?DateInterval
    {
        return $this->resolveDurationOption(
            self::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION,
            $this->config()->getOptionalValue(self::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION, null),
        );
    }

    /**
     * Reads an option which is a duration, is allowed to be absent, and has to be a length of time.
     *
     * Both options this serves are subtracted from now to get a cut-off, and both are the only thing
     * standing between a cut-off and something being deleted or retired. A duration of no time gives a
     * cut-off of now, and a negative one -- which a DateInterval can be, though a duration string can
     * not -- gives a cut-off in the future, at which point the option is not delaying anything but
     * bringing it forward. So neither is accepted, and the option being absent is how a deployment says
     * it does not want the behaviour at all.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function resolveDurationOption(string $option, mixed $value): ?DateInterval
    {
        if ($value === null) {
            return null;
        }

        if ($value instanceof DateInterval) {
            // Checked like any other, rather than trusted for having arrived as the right type. The
            // configuration file is PHP, so an interval can be constructed there and then inverted,
            // which no duration string can express and which the check below is what catches.
            $duration = $value;
        } elseif (is_string($value)) {
            try {
                $duration = new DateInterval($value);
            } catch (Throwable $throwable) {
                throw new ConfigurationError(
                    sprintf('Option "%s" is not a valid duration: %s', $option, $throwable->getMessage()),
                    self::DEFAULT_FILE_NAME,
                );
            }
        } else {
            throw new ConfigurationError(
                sprintf('Option "%s" must be a duration string, %s given.', $option, get_debug_type($value)),
                self::DEFAULT_FILE_NAME,
            );
        }

        // Anchored to the epoch rather than to now, so the answer does not depend on the server's
        // timezone or on which side of a daylight saving transition the configuration is read. An
        // inverted interval lands before the epoch and is caught by the same comparison.
        if ((new DateTimeImmutable('@0'))->add($duration)->getTimestamp() < 1) {
            throw new ConfigurationError(
                sprintf(
                    'Option "%s" is set to no time at all, or to a negative duration. Remove the option ' .
                    'instead.',
                    $option,
                ),
                self::DEFAULT_FILE_NAME,
            );
        }

        return $duration;
    }

    /**
     * Key profile used for Status List Tokens which do not have one set on their own pool.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getVciStatusListKeyProfile(): StatusListKeyProfileEnum
    {
        /** @var mixed $configured */
        $configured = $this->config()->getOptionalValue(self::OPTION_VCI_STATUS_LIST_KEY_PROFILE, null);

        if ($configured === null) {
            return StatusListKeyProfileEnum::DidJwk;
        }

        if ($configured instanceof StatusListKeyProfileEnum) {
            return $configured;
        }

        if (is_string($configured) && ($profile = StatusListKeyProfileEnum::tryFrom($configured)) !== null) {
            return $profile;
        }

        throw new ConfigurationError(
            sprintf(
                'Option "%s" must be one of: %s.',
                self::OPTION_VCI_STATUS_LIST_KEY_PROFILE,
                implode(
                    ', ',
                    array_map(
                        static fn(StatusListKeyProfileEnum $case): string => $case->value,
                        StatusListKeyProfileEnum::cases(),
                    ),
                ),
            ),
            self::DEFAULT_FILE_NAME,
        );
    }

    /**
     * The configured Status List pools.
     *
     * Deliberately a separate top-level option rather than something nested inside the credential
     * configurations: those are returned wholesale as published Credential Issuer metadata, so a
     * private control placed among them would become visible to every wallet.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getVciStatusListPoolBag(): StatusListPoolBag
    {
        if ($this->vciStatusListPoolBag instanceof StatusListPoolBag) {
            return $this->vciStatusListPoolBag;
        }

        $poolBag = StatusListPoolBag::fromConfig(
            $this->config()->getOptionalArray(self::OPTION_VCI_STATUS_LIST_POOLS, []),
            $this->getVciStatusListKeyProfile(),
        );

        $supportedIds = $this->getVciCredentialConfigurationIdsSupported();

        foreach ($poolBag->getAllCredentialConfigurationIds() as $credentialConfigurationId) {
            if (in_array($credentialConfigurationId, $supportedIds, true)) {
                continue;
            }

            // A typo here would otherwise be silent: the pool would simply never be allocated from, and
            // the credentials which were meant to be revocable would be issued without a status claim.
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" lists the credential configuration "%s", which is not one of ' .
                    'the configurations declared under "%s".',
                    (string)$poolBag->getForCredentialConfigurationId($credentialConfigurationId)?->getId(),
                    $credentialConfigurationId,
                    self::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
                ),
                self::DEFAULT_FILE_NAME,
            );
        }

        return $this->vciStatusListPoolBag = $poolBag;
    }

    /**
     * The pool a credential configuration allocates Status List entries from, or null if it is not
     * configured to use them, in which case its credentials are issued without a `status` claim.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getVciStatusListPoolFor(string $credentialConfigurationId): ?StatusListPool
    {
        if (!$this->getVciStatusListEnabled()) {
            return null;
        }

        return $this->getVciStatusListPoolBag()->getForCredentialConfigurationId($credentialConfigurationId);
    }

    /**
     * How long credentials of each configuration remain valid.
     *
     * A separate top-level option for the same reason the pools are: the credential configurations are
     * published wholesale as Credential Issuer metadata, so anything placed among them becomes visible
     * to every wallet.
     *
     * Configurations absent from this map issue credentials which never expire, which is what this
     * module has always done and stays the default. Adding an expiry changes the meaning of credentials
     * that are already being issued, so it is something an operator opts into per configuration rather
     * than something that arrives with an upgrade.
     *
     * @return array<string,\DateInterval>
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getVciCredentialTtls(): array
    {
        if (is_array($this->vciCredentialTtls)) {
            return $this->vciCredentialTtls;
        }

        $supportedIds = $this->getVciCredentialConfigurationIdsSupported();
        $ttls = [];

        /** @var mixed $value */
        foreach ($this->config()->getOptionalArray(self::OPTION_VCI_CREDENTIAL_TTLS, []) as $key => $value) {
            $credentialConfigurationId = (string)$key;

            if (!in_array($credentialConfigurationId, $supportedIds, true)) {
                // Silently ignoring this would leave credentials which were meant to expire being
                // issued without an expiry, and nothing would say so.
                throw new ConfigurationError(
                    sprintf(
                        'Option "%s" sets a lifetime for the credential configuration "%s", which is not ' .
                        'one of the configurations declared under "%s".',
                        self::OPTION_VCI_CREDENTIAL_TTLS,
                        $credentialConfigurationId,
                        self::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
                    ),
                    self::DEFAULT_FILE_NAME,
                );
            }

            $ttls[$credentialConfigurationId] = $this->resolveCredentialTtl($credentialConfigurationId, $value);
        }

        return $this->vciCredentialTtls = $ttls;
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function resolveCredentialTtl(string $credentialConfigurationId, mixed $value): DateInterval
    {
        if (!is_string($value)) {
            throw new ConfigurationError(
                sprintf(
                    'Option "%s" must give the lifetime of "%s" as a duration string, %s given.',
                    self::OPTION_VCI_CREDENTIAL_TTLS,
                    $credentialConfigurationId,
                    get_debug_type($value),
                ),
                self::DEFAULT_FILE_NAME,
            );
        }

        try {
            $ttl = new DateInterval($value);
        } catch (Throwable $throwable) {
            throw new ConfigurationError(
                sprintf(
                    'Option "%s" gives "%s" a lifetime which is not a valid duration: %s',
                    self::OPTION_VCI_CREDENTIAL_TTLS,
                    $credentialConfigurationId,
                    $throwable->getMessage(),
                ),
                self::DEFAULT_FILE_NAME,
            );
        }

        // Anchored to the epoch rather than to now, so the answer does not depend on the server's
        // timezone or on which side of a daylight saving transition the configuration is read.
        if ((new DateTimeImmutable('@0'))->add($ttl)->getTimestamp() < 1) {
            throw new ConfigurationError(
                sprintf(
                    'Option "%s" gives "%s" a lifetime of no time at all, so its credentials would ' .
                    'expire the moment they are issued. Remove the entry to issue credentials which ' .
                    'do not expire.',
                    self::OPTION_VCI_CREDENTIAL_TTLS,
                    $credentialConfigurationId,
                ),
                self::DEFAULT_FILE_NAME,
            );
        }

        return $ttl;
    }

    /**
     * How long a credential of this configuration is valid for, or null if it does not expire.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getVciCredentialTtlFor(string $credentialConfigurationId): ?DateInterval
    {
        return $this->getVciCredentialTtls()[$credentialConfigurationId] ?? null;
    }


    /*****************************************************************************************************************
     * OpenID Connect Dynamic Client Registration related config.
     ****************************************************************************************************************/

    /**
     * Master switch for the OIDC Dynamic Client Registration capability. When
     * disabled (default), the registration and client-configuration endpoints
     * are not served, and `registration_endpoint` is not advertised in OP
     * metadata.
     */
    public function getDcrEnabled(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_DCR_ENABLED, false);
    }

    /**
     * Access-control mode for the registration endpoint: open registration
     * (default) or gated behind an Initial Access Token.
     */
    public function getDcrRegistrationAuth(): DcrRegistrationAuthEnum
    {
        return DcrRegistrationAuthEnum::from(
            $this->config()->getOptionalString(
                self::OPTION_DCR_REGISTRATION_AUTH,
                DcrRegistrationAuthEnum::Open->value,
            ),
        );
    }

    /**
     * Static allowlist of opaque Initial Access Tokens accepted by the
     * registration endpoint when the access mode is
     * DcrRegistrationAuthEnum::InitialAccessToken. Issuance is out-of-band
     * (per spec).
     *
     * @return string[]
     */
    public function getDcrInitialAccessTokens(): array
    {
        $tokens = $this->config()->getOptionalArray(self::OPTION_DCR_INITIAL_ACCESS_TOKENS, []);

        $stringTokens = [];
        /** @var mixed $token */
        foreach ($tokens as $token) {
            if (is_string($token) && $token !== '') {
                $stringTokens[] = $token;
            }
        }

        return $stringTokens;
    }

    /**
     * Whether impersonation protection (OIDC Dynamic Client Registration 1.0,
     * Section 9.1) is enforced. When on (default), the host of `logo_uri`,
     * `policy_uri` and `tos_uri` must match the host of one of the registered
     * `redirect_uris`, otherwise registration is rejected.
     */
    public function getDcrImpersonationProtectionEnabled(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_DCR_IMPERSONATION_PROTECTION_ENABLED, true);
    }

    /**
     * Whether a client registered through Dynamic Client Registration (RFC 7591 / OIDC DCR) is created enabled and
     * therefore immediately usable. When `true` (default) a dynamically registered client can be used right away.
     * Set to `false` to create such clients disabled, so an administrator must review and enable them in the admin
     * UI before they can complete authorization/token flows ("register, then approve"); the client can still read
     * and manage its own registration (RFC 7592) while disabled. This applies only to Dynamic registrations; OpenID
     * Federation automatic registrations (vouched for by their trust chain) are always created enabled.
     */
    public function getDcrRegisteredClientsEnabled(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_DCR_REGISTERED_CLIENTS_ENABLED, true);
    }

    /**
     * Scopes assigned to a Dynamic Client Registration (DCR) client that registers without an explicit `scope`.
     * OpenID Connect Dynamic Client Registration 1.0 makes `scope` OPTIONAL and lets the OP assign a default set;
     * this controls that set. When the option is not configured, it defaults to all scopes this OP supports (so a
     * scope-less dynamic client can request any supported scope, including offline_access). This applies only to
     * Dynamic registrations; manual and OpenID Federation automatic registrations are unaffected.
     *
     * @return string[]
     * @throws \Exception
     */
    public function getDcrDefaultScopes(): array
    {
        $configured = $this->config()->getOptionalArray(
            self::OPTION_DCR_DEFAULT_SCOPES,
            array_keys($this->getScopes()),
        );

        $scopes = [];
        /** @var mixed $scope */
        foreach ($configured as $scope) {
            if (is_string($scope) && $scope !== '') {
                $scopes[] = $scope;
            }
        }

        return $scopes;
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
        /** @psalm-suppress MixedAssignment */
        $credentialConfiguration = $this->getVciCredentialConfigurationsSupported()[$credentialConfigurationId] ?? [];

        if (!is_array($credentialConfiguration)) {
            return [];
        }

        /** @psalm-suppress MixedArrayAccess */
        $claimsConfig = $credentialConfiguration[ClaimsEnum::CredentialMetadata->value][ClaimsEnum::Claims->value] ??
        $credentialConfiguration[ClaimsEnum::Claims->value] ?? [];

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

    /**
     * Get Nonce TTL (validity duration) used for VCI proof-of-possession
     * nonces. If not set, it defaults to 5 minutes.
     *
     * @return DateInterval
     * @throws \Exception
     */
    public function getVciNonceTtl(): DateInterval
    {
        $nonceTtl = $this->config()->getOptionalString(self::OPTION_VCI_NONCE_TTL, null);

        if (is_null($nonceTtl)) {
            return new DateInterval('PT5M');
        }

        return new DateInterval($nonceTtl);
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


    /**
     * Get the full map of a credential configuration ID => JSON-LD context
     * document (as a PHP array).
     *
     * @return mixed[]
     */
    public function getVciCredentialJsonLdContext(): array
    {
        return $this->config()->getOptionalArray(self::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT, []);
    }

    /**
     * Get the JSON-LD context document (as a PHP array) configured for a
     * specific credential configuration ID.
     * Returns null if no context document is configured for the given ID.
     *
     * @return array<mixed>|null
     */
    public function getVciCredentialJsonLdContextFor(string $credentialConfigurationId): ?array
    {
        /** @psalm-suppress MixedAssignment */
        $context = $this->getVciCredentialJsonLdContext()[$credentialConfigurationId] ?? null;

        if (!is_array($context)) {
            return null;
        }

        return $context;
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

    /**
     * Whether the endpoint through which a credential's status can be changed is served.
     *
     * Separate from the Status List capability itself, which only governs whether entries are
     * allocated. Serving this endpoint means accepting revocation requests over the network, which is
     * a decision of its own, and it is off until an operator makes it.
     */
    public function getApiVciCredentialStatusEndpointEnabled(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED, false);
    }

    public function getApiOAuth2TokenIntrospectionEndpointEnabled(): bool
    {
        return $this->config()->getOptionalBoolean(self::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED, false);
    }

    /**
     * Clients allowed to introspect tokens issued to any client, and not only to themselves.
     *
     * Introspection is a protected resource's capability, and which resource servers a deployment has
     * is something only that deployment knows, so it is named here instead of being a property of a
     * client registration: were it registered metadata, a client could grant itself the ability to read
     * every other party's tokens by asking for it during Dynamic Client Registration.
     *
     * @return list<string>
     * @throws \Exception
     */
    public function getApiOAuth2TokenIntrospectionResourceServerClientIds(): array
    {
        $clientIds = $this->config()->getOptionalArray(
            self::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RESOURCE_SERVER_CLIENT_IDS,
            [],
        );

        return array_values(
            array_filter($clientIds, static fn(mixed $clientId): bool => is_string($clientId) && $clientId !== ''),
        );
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
        /** @var mixed $entry */
        $entry = $this->getApiTokens()[$token] ?? null;

        if (!is_array($entry)) {
            return null;
        }

        // Two shapes are accepted. A token may be given a bare list of scopes, which is how this
        // option has always been written, or a settings array which names the token as well. Either
        // of the settings keys marks the second shape, and a bare list can carry neither, since its
        // entries are values rather than keys.
        if (!$this->isApiTokenSettingsShape($entry)) {
            return $entry;
        }

        /** @var mixed $scopes */
        $scopes = $entry[self::KEY_API_TOKEN_SCOPES] ?? null;

        if (is_array($scopes)) {
            return $scopes;
        }

        // Named, but not declaring its scopes under the key for them. They may still be there
        // positionally, which is how a token someone had already annotated with a name would be
        // written, and that token authorized before this option grew a second shape. The settings
        // keys are dropped rather than the whole array returned, since handing back the name would
        // give the token a scope called after itself.
        $positionalScopes = array_diff_key(
            $entry,
            array_flip([self::KEY_API_TOKEN_NAME, self::KEY_API_TOKEN_SCOPES]),
        );

        // Settings which name a token and grant it nothing authorize nothing.
        return $positionalScopes === [] ? null : $positionalScopes;
    }

    /**
     * The name an API token is configured under, or null when it has none.
     *
     * This is what the audit trail records as the actor behind a change. The token itself must never
     * go anywhere near it: it is a bearer secret, and an audit table is exactly the sort of place it
     * would outlive its rotation.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function getApiTokenName(string $token): ?string
    {
        /** @var mixed $entry */
        $entry = $this->getApiTokens()[$token] ?? null;

        if (!is_array($entry)) {
            return null;
        }

        /** @var mixed $name */
        $name = $entry[self::KEY_API_TOKEN_NAME] ?? null;

        if (!is_string($name) || trim($name) === '') {
            return null;
        }

        $name = trim($name);

        // Refused here rather than truncated. A name too long for the column would otherwise make
        // every change this token asks for fail at the point of recording it, on the databases which
        // check, and shortening it silently could quietly merge two principals into one.
        if (mb_strlen($name) > self::MAX_API_TOKEN_NAME_LENGTH) {
            throw new ConfigurationError(
                sprintf(
                    'An API token is named with %d characters, which is more than the %d the status ' .
                    'change audit trail can record. Give it a shorter name.',
                    mb_strlen($name),
                    self::MAX_API_TOKEN_NAME_LENGTH,
                ),
                self::DEFAULT_FILE_NAME,
            );
        }

        return $name;
    }

    /**
     * Whether an API token entry is written as a settings array rather than as a bare list of scopes.
     *
     * @param array<array-key,mixed> $entry
     */
    protected function isApiTokenSettingsShape(array $entry): bool
    {
        // The keys have to hold what the settings shape would hold, not merely be present. A bare
        // list is read by value rather than by key, so one which happens to carry an entry under a
        // key of 'scopes' or 'name' authorized before this option grew a second shape, and quietly
        // ceasing to would be an authorization change nobody asked for.
        return is_array($entry[self::KEY_API_TOKEN_SCOPES] ?? null) ||
        is_string($entry[self::KEY_API_TOKEN_NAME] ?? null);
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

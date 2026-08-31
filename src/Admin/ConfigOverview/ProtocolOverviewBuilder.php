<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin\ConfigOverview;

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Codebooks\ConfigOverviewValueTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\DcrRegistrationAuthEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\AddressPinningModeEnum;
use SimpleSAML\OpenID\Network\DestinationPolicy;
use Throwable;

/**
 * Builds the sections shown on the protocol (Connect) configuration overview screen.
 *
 * Every row which corresponds to a ModuleConfig::OPTION_* constant records that constant, which
 * lets ConfigOptionCoverageTest assert that no protocol option silently goes missing from the
 * screen. When adding a new protocol config option, add it here as well (or, if it must not be
 * displayed, add it to that test's exclusion list together with the reason).
 *
 * Secret values (encryption key, initial access tokens, API tokens, cache adapter credentials,
 * private key passwords) must never be rendered. For those, report whether they are configured.
 */
class ProtocolOverviewBuilder extends AbstractOverviewBuilder
{
    /**
     * Custom scope config keys, mirroring ClaimTranslatorExtractorFactory.
     */
    protected const string SCOPE_KEY_DESCRIPTION = 'description';

    protected const string SCOPE_KEY_CLAIMS = 'claims';

    protected const string SCOPE_KEY_CLAIM_NAME_PREFIX = 'claim_name_prefix';

    protected const string SCOPE_KEY_MULTIPLE_CLAIM_VALUES_ALLOWED = 'are_multiple_claim_values_allowed';


    public function __construct(
        ModuleConfig $moduleConfig,
        Routes $routes,
        DateIntervalFormatter $dateIntervalFormatter,
        LoggerService $logger,
        protected readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
    ) {
        parent::__construct($moduleConfig, $routes, $dateIntervalFormatter, $logger);
    }


    /**
     * @return \SimpleSAML\Module\oidc\Admin\ConfigOverview\Section[]
     * @throws \Exception
     */
    public function build(): array
    {
        return [
            $this->buildEntitySection(),
            $this->buildEndpointsSection(),
            $this->buildTokensSection(),
            $this->buildSignatureKeysSection(),
            $this->buildAuthenticationSection(),
            $this->buildAcrSection(),
            $this->buildScopesAndClaimsSection(),
            $this->buildRequestObjectSection(),
            $this->buildDynamicClientRegistrationSection(),
            $this->buildCacheSection(),
            $this->buildOutboundHttpSection(),
            $this->buildApiSection(),
        ];
    }


    /**
     * @throws \Exception
     */
    protected function buildEntitySection(): Section
    {
        return new Section(
            Translate::noop('Entity'),
            'entity',
            $this->buildIssuerRow(
                null,
                Translate::noop(
                    'Not explicitly configured, so it is derived from the current HTTP host. This ' .
                    'means the issuer can change depending on how the OP is reached.',
                ),
            ),
            new Row(
                Translate::noop('OpenID Connect Discovery URL'),
                $this->routes->urlConfiguration(),
                ConfigOverviewValueTypeEnum::Url,
            ),
            new Row(
                Translate::noop('OAuth2 Authorization Server Metadata URL'),
                $this->routes->urlOAuth2Configuration(),
                ConfigOverviewValueTypeEnum::Url,
            ),
        );
    }


    protected function buildEndpointsSection(): Section
    {
        $rows = [
            new Row(
                Translate::noop('Authorization'),
                $this->routes->urlAuthorization(),
                ConfigOverviewValueTypeEnum::Url,
            ),
            new Row(
                Translate::noop('Pushed Authorization Request (PAR)'),
                $this->routes->urlPushedAuthorizationRequest(),
                ConfigOverviewValueTypeEnum::Url,
            ),
            new Row(
                Translate::noop('Token'),
                $this->routes->urlToken(),
                ConfigOverviewValueTypeEnum::Url,
            ),
            new Row(
                Translate::noop('UserInfo'),
                $this->routes->urlUserInfo(),
                ConfigOverviewValueTypeEnum::Url,
            ),
            new Row(
                Translate::noop('JWKS'),
                $this->routes->urlJwks(),
                ConfigOverviewValueTypeEnum::Url,
            ),
            new Row(
                Translate::noop('End Session'),
                $this->routes->urlEndSession(),
                ConfigOverviewValueTypeEnum::Url,
            ),
        ];

        // These rows display URLs rather than options, so a bad OPTION_DCR_ENABLED is reported on its
        // own row in the Dynamic Client Registration section instead of here. Resolved defensively
        // only so that it cannot take this section down on the way past.
        $isDcrEnabled = false;

        try {
            $isDcrEnabled = $this->moduleConfig->getDcrEnabled();
        } catch (Throwable) {
            // Reported on the Dynamic Client Registration Enabled row, where the option is named.
        }

        if ($isDcrEnabled) {
            $rows[] = new Row(
                Translate::noop('Client Registration'),
                $this->routes->urlRegistration(),
                ConfigOverviewValueTypeEnum::Url,
            );
        }

        return new Section(Translate::noop('Endpoints'), 'endpoints', ...$rows);
    }


    /**
     * @throws \Exception
     */
    protected function buildTokensSection(): Section
    {
        return new Section(
            Translate::noop('Tokens and cryptography'),
            'tokens',
            $this->guardRow(
                Translate::noop('Authorization Code TTL'),
                ModuleConfig::OPTION_TOKEN_AUTHORIZATION_CODE_TTL,
                fn(): Row => $this->buildDurationRow(
                    Translate::noop('Authorization Code TTL'),
                    $this->moduleConfig->getAuthCodeDuration(),
                    ModuleConfig::OPTION_TOKEN_AUTHORIZATION_CODE_TTL,
                ),
            ),
            $this->guardRow(
                Translate::noop('Access Token TTL'),
                ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_TTL,
                fn(): Row => $this->buildDurationRow(
                    Translate::noop('Access Token TTL'),
                    $this->moduleConfig->getAccessTokenDuration(),
                    ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_TTL,
                ),
            ),
            $this->guardRow(
                Translate::noop('Refresh Token TTL'),
                ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL,
                fn(): Row => $this->buildDurationRow(
                    Translate::noop('Refresh Token TTL'),
                    $this->moduleConfig->getRefreshTokenDuration(),
                    ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL,
                ),
            ),
            $this->guardRow(
                Translate::noop('Timestamp Validation Leeway'),
                ModuleConfig::OPTION_TIMESTAMP_VALIDATION_LEEWAY,
                fn(): Row => $this->buildDurationRow(
                    Translate::noop('Timestamp Validation Leeway'),
                    $this->moduleConfig->getTimestampValidationLeeway(),
                    ModuleConfig::OPTION_TIMESTAMP_VALIDATION_LEEWAY,
                    Translate::noop(
                        'Tolerance allowed when validating timestamp claims (exp, iat, nbf) on JWS artifacts.',
                    ),
                ),
            ),
            $this->guardRow(
                Translate::noop('Encryption Key'),
                ModuleConfig::OPTION_ENCRYPTION_KEY,
                fn(): Row => new Row(
                    Translate::noop('Encryption Key'),
                    $this->moduleConfig->isEncryptionKeyConfigured() ?
                    Translate::noop('Dedicated encryption key configured') :
                    Translate::noop('Derived from the SimpleSAMLphp secret salt'),
                    ConfigOverviewValueTypeEnum::Text,
                    ModuleConfig::OPTION_ENCRYPTION_KEY,
                    Translate::noop(
                        'Protects issued authorization codes and refresh tokens. The value itself is ' .
                        'a secret and is never shown here. Changing it invalidates all outstanding ' .
                        'encrypted artifacts.',
                    ),
                ),
            ),
        );
    }


    /**
     * @throws \Exception
     */
    protected function buildSignatureKeysSection(): Section
    {
        $keyPairBag = null;
        $error = null;

        try {
            $keyPairBag = $this->moduleConfig->getProtocolSignatureKeyPairBag();
        } catch (Throwable $exception) {
            $error = $this->describeResolutionError(
                $exception,
                ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS,
            );
        }

        return new Section(
            Translate::noop('Signature algorithms and public keys'),
            'signature-keys',
            new Row(
                Translate::noop('Protocol Signature Key Pairs'),
                $keyPairBag,
                ConfigOverviewValueTypeEnum::SignatureKeyPairs,
                ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS,
                Translate::noop(
                    'Order matters. The first entry is the default signing key, and is used when a ' .
                    'client does not designate a signing algorithm. Additional entries are advertised ' .
                    'on the JWKS endpoint, which is what makes key rollover possible.',
                ),
                $error,
            ),
        );
    }


    /**
     * @throws \Exception
     */
    protected function buildAuthenticationSection(): Section
    {
        return new Section(
            Translate::noop('Authentication'),
            'authentication',
            $this->guardRow(
                Translate::noop('Default Authentication Source'),
                ModuleConfig::OPTION_AUTH_SOURCE,
                fn(): Row => new Row(
                    Translate::noop('Default Authentication Source'),
                    $this->moduleConfig->getDefaultAuthSourceId(),
                    ConfigOverviewValueTypeEnum::RawText,
                    ModuleConfig::OPTION_AUTH_SOURCE,
                    Translate::noop(
                        'Used for clients which do not have their own authentication source set.',
                    ),
                ),
            ),
            $this->guardRow(
                Translate::noop('User Identifier Attributes'),
                ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE,
                fn(): Row => new Row(
                    Translate::noop('User Identifier Attributes'),
                    $this->moduleConfig->getUserIdentifierAttributes(),
                    ConfigOverviewValueTypeEnum::StringList,
                    ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE,
                    Translate::noop(
                        'Consulted in the order shown. The first attribute actually present in the ' .
                        'released attributes is used as the user identifier, and as the default ' .
                        "source for the 'sub' claim.",
                    ),
                ),
            ),
            $this->guardRow(
                Translate::noop('Authentication Processing Filters'),
                ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS,
                fn(): Row => new Row(
                    Translate::noop('Authentication Processing Filters'),
                    $this->buildAuthProcFilterList(),
                    ConfigOverviewValueTypeEnum::StringList,
                    ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS,
                    Translate::noop(
                        'Run for every OIDC authentication, in the order shown, which is by ' .
                        'priority. Per-client filters are merged into the same chain by priority as ' .
                        'well.',
                    ),
                ),
            ),
        );
    }


    /**
     * @throws \Exception
     */
    protected function buildAcrSection(): Section
    {
        return new Section(
            Translate::noop('Authentication Context Class References (ACRs)'),
            'acrs',
            $this->guardRow(
                Translate::noop('Supported ACRs'),
                ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED,
                fn(): Row => new Row(
                    Translate::noop('Supported ACRs'),
                    $this->moduleConfig->getAcrValuesSupported(),
                    ConfigOverviewValueTypeEnum::StringList,
                    ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED,
                    Translate::noop("Published in the OP discovery document as 'acr_values_supported'."),
                ),
            ),
            $this->guardRow(
                Translate::noop('Authentication Sources to ACRs Map'),
                ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP,
                fn(): Row => new Row(
                    Translate::noop('Authentication Sources to ACRs Map'),
                    $this->moduleConfig->getAuthSourcesToAcrValuesMap(),
                    ConfigOverviewValueTypeEnum::StringMap,
                    ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP,
                    Translate::noop('ACRs are listed in order of importance, most important first.'),
                ),
            ),
            $this->guardRow(
                Translate::noop('Forced ACR for Cookie Authentication'),
                ModuleConfig::OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION,
                function (): Row {
                    $forcedAcrValue = $this->moduleConfig->getForcedAcrValueForCookieAuthentication();

                    return new Row(
                        Translate::noop('Forced ACR for Cookie Authentication'),
                        $forcedAcrValue ?? Translate::noop('N/A'),
                        // A configured ACR is data, the 'N/A' placeholder is UI text.
                        is_null($forcedAcrValue) ?
                        ConfigOverviewValueTypeEnum::Text :
                        ConfigOverviewValueTypeEnum::RawText,
                        ModuleConfig::OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION,
                        is_null($forcedAcrValue) ? Translate::noop(
                            'No specific ACR is forced, so the resulting ACR is one of those ' .
                            'supported by the auth source used during session creation.',
                        ) : null,
                    );
                },
            ),
        );
    }


    /**
     * @throws \Exception
     */
    protected function buildScopesAndClaimsSection(): Section
    {
        // The scope list pulls in Verifiable Credential scopes, so a malformed credential
        // configuration can make this throw even though it is not a protocol option.
        $scopes = [];
        $error = null;

        try {
            $scopes = $this->buildScopeList();
        } catch (Throwable $exception) {
            $error = $this->describeResolutionError($exception, ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES);
        }

        return new Section(
            Translate::noop('Scopes and claims'),
            'scopes-and-claims',
            new Row(
                Translate::noop('Scopes'),
                $scopes,
                ConfigOverviewValueTypeEnum::Scopes,
                ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES,
                // Suppressed on failure, so the description does not contradict an empty list.
                is_null($error) ? Translate::noop(
                    'Standard scopes are always available. Custom scopes come from configuration, ' .
                    'while Verifiable Credential scopes are derived from the supported credential ' .
                    'configurations, and only exist while that capability is enabled.',
                ) : null,
                $error,
            ),
            $this->guardRow(
                Translate::noop('SAML Attribute to OIDC Claim Translation'),
                ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE,
                fn(): Row => new Row(
                    Translate::noop('SAML Attribute to OIDC Claim Translation'),
                    $this->claimTranslatorExtractor->getTranslationTable(),
                    ConfigOverviewValueTypeEnum::Json,
                    ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE,
                    Translate::noop(
                        'The effective table: module defaults with the configured translation table ' .
                        "merged over them, the user identifier attributes prepended to the 'sub' " .
                        'claim, and any per-scope claim name prefixes already applied.',
                    ),
                ),
            ),
            $this->guardRow(
                Translate::noop("Publish 'claims_supported' in Discovery"),
                ModuleConfig::OPTION_PROTOCOL_DISCOVERY_SHOW_CLAIMS_SUPPORTED,
                fn(): Row => new Row(
                    Translate::noop("Publish 'claims_supported' in Discovery"),
                    $this->yesNo($this->moduleConfig->getProtocolDiscoveryShowClaimsSupported()),
                    ConfigOverviewValueTypeEnum::Text,
                    ModuleConfig::OPTION_PROTOCOL_DISCOVERY_SHOW_CLAIMS_SUPPORTED,
                    Translate::noop(
                        'When enabled, the discovery document lists all claims for which a ' .
                        'translation is defined.',
                    ),
                ),
            ),
        );
    }


    /**
     * @throws \Exception
     */
    protected function buildRequestObjectSection(): Section
    {
        // Both feed rows other than their own, so they are resolved defensively rather than left to
        // take the section down. Each is reported on its own row, where the option is named.
        $requestUriParameterSupported = false;
        $isFederationEnabled = false;

        try {
            $requestUriParameterSupported = $this->moduleConfig->getRequestUriParameterSupported();
        } catch (Throwable) {
            // Reported on the request_uri parameter row below.
        }

        try {
            // RequestParamsResolver only takes the federation by-reference path when federation is
            // enabled, so without it the allowlist is never consulted.
            $isFederationEnabled = $this->moduleConfig->getFederationEnabled();
        } catch (Throwable) {
            // Reported on the federation screen, which owns OPTION_FEDERATION_ENABLED.
        }

        return new Section(
            Translate::noop('Request Object and Pushed Authorization Requests'),
            'request-object',
            $this->guardRow(
                Translate::noop('Require Pushed Authorization Requests (PAR)'),
                ModuleConfig::OPTION_REQUIRE_PUSHED_AUTHORIZATION_REQUESTS,
                fn(): Row => new Row(
                    Translate::noop('Require Pushed Authorization Requests (PAR)'),
                    $this->yesNo($this->moduleConfig->getRequirePushedAuthorizationRequests()),
                    ConfigOverviewValueTypeEnum::Text,
                    ModuleConfig::OPTION_REQUIRE_PUSHED_AUTHORIZATION_REQUESTS,
                    Translate::noop(
                        'When required, authorization requests which do not reference a previously ' .
                        'pushed request are rejected.',
                    ),
                ),
            ),
            $this->guardRow(
                Translate::noop('PAR Request URI TTL'),
                ModuleConfig::OPTION_PAR_REQUEST_URI_TTL,
                fn(): Row => $this->buildDurationRow(
                    Translate::noop('PAR Request URI TTL'),
                    $this->moduleConfig->getParRequestUriTtl(),
                    ModuleConfig::OPTION_PAR_REQUEST_URI_TTL,
                ),
            ),
            $this->guardRow(
                Translate::noop('Require Signed Request Object'),
                ModuleConfig::OPTION_REQUIRE_SIGNED_REQUEST_OBJECT,
                fn(): Row => new Row(
                    Translate::noop('Require Signed Request Object'),
                    $this->yesNo($this->moduleConfig->getRequireSignedRequestObject()),
                    ConfigOverviewValueTypeEnum::Text,
                    ModuleConfig::OPTION_REQUIRE_SIGNED_REQUEST_OBJECT,
                    Translate::noop(
                        'Requires every Relying Party to sign its Request Objects, and the OP to ' .
                        'have their signing keys available.',
                    ),
                ),
            ),
            $this->guardRow(
                Translate::noop("Support 'request_uri' Parameter"),
                ModuleConfig::OPTION_REQUEST_URI_PARAMETER_SUPPORTED,
                fn(): Row => new Row(
                    Translate::noop("Support 'request_uri' Parameter"),
                    $this->yesNo($this->moduleConfig->getRequestUriParameterSupported()),
                    ConfigOverviewValueTypeEnum::Text,
                    ModuleConfig::OPTION_REQUEST_URI_PARAMETER_SUPPORTED,
                    $requestUriParameterSupported ?
                    Translate::noop(
                        'The OP fetches Request Objects by reference, which means outbound HTTP ' .
                        'requests to URIs supplied in authorization requests. Disable it to remove ' .
                        'that surface entirely. Pushed Authorization Request URIs (urn form) are ' .
                        'not affected.',
                    ) :
                    Translate::noop('Request Objects can only be passed by value, and through PAR.'),
                ),
            ),
            $this->guardRow(
                Translate::noop('Allowed Request URI Prefixes for Federation Candidates'),
                ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES,
                function () use ($requestUriParameterSupported, $isFederationEnabled): Row {
                    // null means "allow any", an empty array means "deny all" (also the default),
                    // and a non-empty array is the actual allowlist.
                    $allowedPrefixes = $this->moduleConfig->getFederationRequestUriAllowedPrefixes();

                    return new Row(
                        Translate::noop('Allowed Request URI Prefixes for Federation Candidates'),
                        match (true) {
                            is_null($allowedPrefixes) => Translate::noop('Any request URI is allowed'),
                            $allowedPrefixes === [] => Translate::noop(
                                'None, so no such request URI is fetched',
                            ),
                            default => $allowedPrefixes,
                        },
                        is_array($allowedPrefixes) && $allowedPrefixes !== [] ?
                        ConfigOverviewValueTypeEnum::StringList :
                        ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES,
                        $isFederationEnabled ? Translate::noop(
                            'Applies only to OpenID Federation candidates, that is, clients which ' .
                            'are not registered in storage. For registered clients the request URI ' .
                            'must match one of their own registered request URIs exactly.',
                        ) : Translate::noop(
                            'Not used, since OpenID Federation is disabled and the by-reference ' .
                            'fetch for federation candidates therefore never runs.',
                        ),
                        ($isFederationEnabled && $requestUriParameterSupported && is_null($allowedPrefixes)) ?
                        Translate::noop(
                            'Any request URI supplied by an unregistered federation candidate will ' .
                            'be fetched, which is a server-side request forgery surface. Configure ' .
                            'explicit prefixes instead.',
                        ) : null,
                    );
                },
            ),
            $this->guardRow(
                Translate::noop("'request_uri' Fetch Timeout (seconds)"),
                ModuleConfig::OPTION_REQUEST_URI_FETCH_TIMEOUT,
                fn(): Row => new Row(
                    // The unit lives in the label so that it stays translatable, while the value
                    // itself is rendered as configured.
                    Translate::noop("'request_uri' Fetch Timeout (seconds)"),
                    (string)$this->moduleConfig->getRequestUriFetchTimeout(),
                    ConfigOverviewValueTypeEnum::RawText,
                    ModuleConfig::OPTION_REQUEST_URI_FETCH_TIMEOUT,
                ),
            ),
            $this->guardRow(
                Translate::noop("'request_uri' Maximum Response Size (bytes)"),
                ModuleConfig::OPTION_REQUEST_URI_MAX_SIZE_BYTES,
                fn(): Row => new Row(
                    Translate::noop("'request_uri' Maximum Response Size (bytes)"),
                    $this->formatBytes($this->moduleConfig->getRequestUriMaxSizeBytes()),
                    ConfigOverviewValueTypeEnum::RawText,
                    ModuleConfig::OPTION_REQUEST_URI_MAX_SIZE_BYTES,
                ),
            ),
        );
    }


    /**
     * @throws \Exception
     */
    protected function buildDynamicClientRegistrationSection(): Section
    {
        // Each of these decides a warning on a row other than its own, so they are resolved
        // defensively here and resolved again inside the guard of the row which displays them - that
        // second read is what reports a malformed value in the place an administrator will look.
        $isEnabled = false;
        $registrationAuth = null;
        $initialAccessTokenCount = 0;

        try {
            $isEnabled = $this->moduleConfig->getDcrEnabled();
        } catch (Throwable) {
            // Reported on the Enabled row below.
        }

        try {
            $registrationAuth = $this->moduleConfig->getDcrRegistrationAuth();
        } catch (Throwable) {
            // Reported on the Registration Access Control row below.
        }

        try {
            $initialAccessTokenCount = count($this->moduleConfig->getDcrInitialAccessTokens());
        } catch (Throwable) {
            // Reported on the Initial Access Tokens row below.
        }

        $hasUnusableInitialAccessTokenMode = $isEnabled &&
        $registrationAuth === DcrRegistrationAuthEnum::InitialAccessToken &&
        $initialAccessTokenCount === 0;

        return new Section(
            Translate::noop('Dynamic Client Registration'),
            'dynamic-client-registration',
            $this->guardRow(
                Translate::noop('Enabled'),
                ModuleConfig::OPTION_DCR_ENABLED,
                function (): Row {
                    $isEnabled = $this->moduleConfig->getDcrEnabled();

                    return new Row(
                        Translate::noop('Enabled'),
                        $this->yesNo($isEnabled),
                        ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_DCR_ENABLED,
                        $isEnabled ? null : Translate::noop(
                            'The registration and client configuration endpoints are not served, ' .
                            "and the 'registration_endpoint' claim is not advertised in OP metadata.",
                        ),
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('Registration Access Control'),
                ModuleConfig::OPTION_DCR_REGISTRATION_AUTH,
                function () use ($isEnabled): Row {
                    $registrationAuth = $this->moduleConfig->getDcrRegistrationAuth();

                    return new Row(
                        Translate::noop('Registration Access Control'),
                        $this->describeRegistrationAuth($registrationAuth),
                        ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_DCR_REGISTRATION_AUTH,
                        null,
                        ($isEnabled && $registrationAuth === DcrRegistrationAuthEnum::Open) ?
                        Translate::noop(
                            'Registration is open, so anyone can register a client without ' .
                            'authenticating. Protect the endpoint from abuse using rate limiting at ' .
                            'the web server level.',
                        ) : null,
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('Initial Access Tokens'),
                ModuleConfig::OPTION_DCR_INITIAL_ACCESS_TOKENS,
                fn(): Row => $this->buildSecretCountRow(
                    Translate::noop('Initial Access Tokens'),
                    count($this->moduleConfig->getDcrInitialAccessTokens()),
                    ModuleConfig::OPTION_DCR_INITIAL_ACCESS_TOKENS,
                    Translate::noop('The tokens themselves are secrets and are never shown here.'),
                    $hasUnusableInitialAccessTokenMode ? Translate::noop(
                        'Registration requires an Initial Access Token, but none are configured, so ' .
                        'every registration attempt will be rejected.',
                    ) : null,
                ),
            ),
            $this->guardRow(
                Translate::noop('Impersonation Protection'),
                ModuleConfig::OPTION_DCR_IMPERSONATION_PROTECTION_ENABLED,
                function () use ($isEnabled): Row {
                    $isProtectionEnabled = $this->moduleConfig->getDcrImpersonationProtectionEnabled();

                    return new Row(
                        Translate::noop('Impersonation Protection'),
                        $this->yesNo($isProtectionEnabled),
                        ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_DCR_IMPERSONATION_PROTECTION_ENABLED,
                        Translate::noop(
                            "When enabled, the host of a client's logo_uri, policy_uri and tos_uri " .
                            'must match the host of one of its redirect URIs.',
                        ),
                        ($isEnabled && !$isProtectionEnabled) ? Translate::noop(
                            'Disabled, so a rogue client can reuse the branding and links of a ' .
                            'legitimate one during registration.',
                        ) : null,
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('Registered Clients Are Enabled'),
                ModuleConfig::OPTION_DCR_REGISTERED_CLIENTS_ENABLED,
                fn(): Row => new Row(
                    Translate::noop('Registered Clients Are Enabled'),
                    $this->yesNo($this->moduleConfig->getDcrRegisteredClientsEnabled()),
                    ConfigOverviewValueTypeEnum::Text,
                    ModuleConfig::OPTION_DCR_REGISTERED_CLIENTS_ENABLED,
                    Translate::noop(
                        'When disabled, dynamically registered clients must be reviewed and enabled ' .
                        'by an administrator before they can obtain tokens.',
                    ),
                ),
            ),
            $this->buildDcrDefaultScopesRow(),
        );
    }


    /**
     * The default scopes row keeps the try/catch shape rather than guardRow(), because it still shows
     * the option's own note alongside the failure instead of replacing the whole row with 'N/A'.
     */
    protected function buildDcrDefaultScopesRow(): Row
    {
        // Falls back to every supported scope when unset, which walks the same Verifiable Credential
        // scope resolution that can throw on a malformed credential configuration.
        $defaultScopes = [];
        $defaultScopesError = null;
        $areDefaultScopesConfigured = false;

        try {
            $areDefaultScopesConfigured = $this->moduleConfig->config()
                ->hasValue(ModuleConfig::OPTION_DCR_DEFAULT_SCOPES);
            $defaultScopes = $this->moduleConfig->getDcrDefaultScopes();
        } catch (Throwable $exception) {
            $defaultScopesError = $this->describeResolutionError(
                $exception,
                ModuleConfig::OPTION_DCR_DEFAULT_SCOPES,
            );
        }

        return new Row(
            Translate::noop('Default Scopes for Scope-less Registrations'),
            $defaultScopes,
            ConfigOverviewValueTypeEnum::StringList,
            ModuleConfig::OPTION_DCR_DEFAULT_SCOPES,
            // Suppressed on failure: the fallback set could not be resolved, so claiming it
            // contains every supported scope would contradict the warning and the empty value.
            ($areDefaultScopesConfigured || !is_null($defaultScopesError)) ? null : Translate::noop(
                'Not configured, so this falls back to every scope this OP supports, meaning a ' .
                "client which registers without a 'scope' may request any of them, including " .
                "'offline_access'.",
            ),
            $defaultScopesError,
        );
    }


    /**
     * @throws \Exception
     */
    protected function buildCacheSection(): Section
    {
        // Only asserted to be a string when it is read, so a value of another type throws here. This
        // screen is where an administrator goes to find that out, so it must not take it down.
        $isCachingActive = false;

        try {
            $isCachingActive = !is_null($this->moduleConfig->getProtocolCacheAdapterClass());
        } catch (Throwable) {
            // Reported on its own row below, where the option which failed to resolve is named.
        }

        $isUserEntityCacheDurationConfigured = $this->moduleConfig->config()
            ->hasValue(ModuleConfig::OPTION_PROTOCOL_USER_ENTITY_CACHE_DURATION);

        // Notes are kept as whole sentences rather than concatenated fragments, so that each one is
        // a single message which translators can actually translate.
        if ($isUserEntityCacheDurationConfigured) {
            $userEntityCacheDurationNote = $isCachingActive ?
            null :
            Translate::noop('Not used, since no cache adapter is configured.');
        } else {
            $userEntityCacheDurationNote = $isCachingActive ?
            Translate::noop('Not configured, so this falls back to the SimpleSAMLphp session duration.') :
            Translate::noop(
                'Not configured, so this falls back to the SimpleSAMLphp session duration. Not used ' .
                'anyway, since no cache adapter is configured.',
            );
        }

        return new Section(
            Translate::noop('Cache'),
            'cache',
            $this->guardRow(
                Translate::noop('Cache Adapter'),
                ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER,
                function () use ($isCachingActive): Row {
                    $adapterClass = $this->moduleConfig->getProtocolCacheAdapterClass();

                    return new Row(
                        Translate::noop('Cache Adapter'),
                        $adapterClass ?? Translate::noop('N/A'),
                        // A configured adapter class is data, the 'N/A' placeholder is UI text.
                        $isCachingActive ?
                        ConfigOverviewValueTypeEnum::RawText :
                        ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER,
                        $isCachingActive ? null : Translate::noop(
                            'Not set, so no protocol caching is performed. Setting a cache adapter ' .
                            'is recommended in production.',
                        ),
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('Cache Adapter Arguments'),
                ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER_ARGUMENTS,
                fn(): Row => $this->buildSecretCountRow(
                    Translate::noop('Cache Adapter Arguments'),
                    count($this->moduleConfig->getProtocolCacheAdapterArguments()),
                    ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER_ARGUMENTS,
                    Translate::noop(
                        'Values are not shown, since adapter arguments can carry connection credentials.',
                    ),
                ),
            ),
            $this->guardRow(
                Translate::noop('User Entity Cache Duration'),
                ModuleConfig::OPTION_PROTOCOL_USER_ENTITY_CACHE_DURATION,
                fn(): Row => $this->buildDurationRow(
                    Translate::noop('User Entity Cache Duration'),
                    $this->moduleConfig->getProtocolUserEntityCacheDuration(),
                    ModuleConfig::OPTION_PROTOCOL_USER_ENTITY_CACHE_DURATION,
                    $userEntityCacheDurationNote,
                ),
            ),
            $this->guardRow(
                Translate::noop('Client Entity Cache Duration'),
                ModuleConfig::OPTION_PROTOCOL_CLIENT_ENTITY_CACHE_DURATION,
                fn(): Row => $this->buildDurationRow(
                    Translate::noop('Client Entity Cache Duration'),
                    $this->moduleConfig->getProtocolClientEntityCacheDuration(),
                    ModuleConfig::OPTION_PROTOCOL_CLIENT_ENTITY_CACHE_DURATION,
                    $isCachingActive ?
                    null :
                    Translate::noop('Not used, since no cache adapter is configured.'),
                ),
            ),
        );
    }


    /**
     * @throws \Exception
     */
    protected function buildOutboundHttpSection(): Section
    {
        return new Section(
            Translate::noop('Outbound HTTP requests'),
            'outbound-http',
            $this->guardRow(
                Translate::noop('Protocol HTTP Client Options'),
                ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS,
                fn(): Row => $this->buildHttpClientOptionsRow(
                    Translate::noop('Protocol HTTP Client Options'),
                    $this->moduleConfig->getProtocolHttpClientOptions(),
                    ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS,
                    Translate::noop(
                        "Applied to protocol-layer fetches, such as a client's 'jwks_uri' or a 'request_uri'.",
                    ),
                    Translate::noop(
                        "Applied to protocol-layer fetches, such as a client's 'jwks_uri' or a " .
                        "'request_uri'. Not set, so the library defaults apply, including TLS verification.",
                    ),
                ),
            ),
            $this->guardRow(
                Translate::noop('Back-Channel Logout HTTP Client Options'),
                ModuleConfig::OPTION_BACKCHANNEL_LOGOUT_HTTP_CLIENT_OPTIONS,
                fn(): Row => $this->buildHttpClientOptionsRow(
                    Translate::noop('Back-Channel Logout HTTP Client Options'),
                    $this->moduleConfig->getBackChannelLogoutHttpClientOptions(),
                    ModuleConfig::OPTION_BACKCHANNEL_LOGOUT_HTTP_CLIENT_OPTIONS,
                    Translate::noop(
                        "Applied to Back-Channel Logout requests sent to a client's " .
                        "'backchannel_logout_uri'. Merged over a 3 second connect and total timeout.",
                    ),
                    Translate::noop(
                        "Applied to Back-Channel Logout requests sent to a client's " .
                        "'backchannel_logout_uri'. Merged over a 3 second connect and total timeout. " .
                        'Not set, so TLS verification stays enabled.',
                    ),
                ),
            ),
            ...$this->buildDestinationPolicyRows(),
        );
    }


    /**
     * Where this OP is willing to send outbound requests.
     *
     * Shown alongside the client options because the two answer different halves of the same question: the
     * options say how a fetch is made, these say whether it may be made at all. Both apply to every
     * destination a client or a federation names.
     *
     * Every value here comes from a getter that rejects a malformed value, and this screen is what an
     * administrator opens when the configuration is malformed, so each row resolves its own option inside
     * guardRow() rather than up front.
     *
     * @return \SimpleSAML\Module\oidc\Admin\ConfigOverview\Row[]
     */
    protected function buildDestinationPolicyRows(): array
    {
        return [
            $this->guardRow(
                Translate::noop('Outbound Allowed Schemes'),
                ModuleConfig::OPTION_OUTBOUND_ALLOWED_SCHEMES,
                function (): Row {
                    $allowedSchemes = $this->moduleConfig->getOutboundAllowedSchemes();
                    // The getter only establishes that these are strings. Whether they are usable is the
                    // policy's own judgement, and it is made in its constructor, so a value that would be
                    // refused there has to be refused here rather than displayed as if it applied.
                    new DestinationPolicy(allowedSchemes: $allowedSchemes);

                    return new Row(
                        Translate::noop('Outbound Allowed Schemes'),
                        $allowedSchemes,
                        ConfigOverviewValueTypeEnum::StringList,
                        ModuleConfig::OPTION_OUTBOUND_ALLOWED_SCHEMES,
                        Translate::noop('Schemes an outbound request may use.'),
                        // Trimmed as the policy trims, so a padded ' http ' is reported as the plain http
                        // it will actually permit.
                        in_array(
                            'http',
                            array_map(
                                fn(string $scheme): string => strtolower(trim($scheme)),
                                $allowedSchemes,
                            ),
                            true,
                        ) ?
                        Translate::noop(
                            'Plain http is permitted, so an outbound fetch can be read and altered in ' .
                            'transit.',
                        ) :
                        null,
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('Outbound Allowed Hosts'),
                ModuleConfig::OPTION_OUTBOUND_ALLOWED_HOSTS,
                function (): Row {
                    $allowedHosts = $this->moduleConfig->getOutboundAllowedHosts();
                    new DestinationPolicy(allowedHosts: $allowedHosts);

                    return new Row(
                        Translate::noop('Outbound Allowed Hosts'),
                        $allowedHosts,
                        ConfigOverviewValueTypeEnum::StringList,
                        ModuleConfig::OPTION_OUTBOUND_ALLOWED_HOSTS,
                        $allowedHosts === [] ?
                        Translate::noop('None, so every destination is subject to the address check.') :
                        Translate::noop(
                            'Permitted whatever they resolve to. The address check and the address ' .
                            'pinning are both skipped for these.',
                        ),
                        $allowedHosts === [] ?
                        null :
                        Translate::noop(
                            'Allowing a host trusts whoever controls that name with where the request ' .
                            'goes. Keep this to destinations this deployment operates itself.',
                        ),
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('Outbound Allowed Address Ranges'),
                ModuleConfig::OPTION_OUTBOUND_ALLOWED_CIDRS,
                function (): Row {
                    $allowedCidrs = $this->moduleConfig->getOutboundAllowedCidrs();
                    // A range that can never match would otherwise be shown as a working exemption.
                    new DestinationPolicy(allowedCidrs: $allowedCidrs);

                    return new Row(
                        Translate::noop('Outbound Allowed Address Ranges'),
                        $allowedCidrs,
                        ConfigOverviewValueTypeEnum::StringList,
                        ModuleConfig::OPTION_OUTBOUND_ALLOWED_CIDRS,
                        $allowedCidrs === [] ?
                        Translate::noop('None, so only public addresses may be reached.') :
                        Translate::noop('Permitted alongside the public addresses.'),
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('Outbound Address Pinning'),
                ModuleConfig::OPTION_OUTBOUND_ADDRESS_PINNING_MODE,
                function (): Row {
                    $pinningMode = $this->moduleConfig->getOutboundAddressPinningMode();

                    return new Row(
                        Translate::noop('Outbound Address Pinning'),
                        $pinningMode->value,
                        ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_OUTBOUND_ADDRESS_PINNING_MODE,
                        Translate::noop(
                            'Whether the connection must go to the address that was validated, rather ' .
                            'than the host being resolved a second time.',
                        ),
                        $pinningMode === AddressPinningModeEnum::Disabled ?
                        Translate::noop(
                            'Pinning is off, so a host can resolve to a permitted address for the check ' .
                            'and to another one for the connection.',
                        ) :
                        null,
                    );
                },
            ),
        ];
    }


    /**
     * @throws \Exception
     */
    protected function buildApiSection(): Section
    {
        // All three decide something on a row other than their own - whether the endpoint row below is
        // shown at all, in the first two cases - so they are resolved defensively and resolved again
        // inside the guard of the row which displays them.
        $isApiEnabled = false;
        $isIntrospectionEnabled = false;
        $apiTokenCount = 0;

        try {
            $isApiEnabled = $this->moduleConfig->getApiEnabled();
        } catch (Throwable) {
            // Reported on the API Enabled row below.
        }

        try {
            $isIntrospectionEnabled = $this->moduleConfig->getApiOAuth2TokenIntrospectionEndpointEnabled();
        } catch (Throwable) {
            // Reported on the Token Introspection Endpoint Enabled row below.
        }

        try {
            $apiTokenCount = count($this->moduleConfig->getApiTokens() ?? []);
        } catch (Throwable) {
            // Reported on the API Tokens row below.
        }

        $rows = [
            $this->guardRow(
                Translate::noop('API Enabled'),
                ModuleConfig::OPTION_API_ENABLED,
                fn(): Row => new Row(
                    Translate::noop('API Enabled'),
                    $this->yesNo($this->moduleConfig->getApiEnabled()),
                    ConfigOverviewValueTypeEnum::Text,
                    ModuleConfig::OPTION_API_ENABLED,
                    Translate::noop('Master switch for the module specific (non-protocol) API endpoints.'),
                ),
            ),
            $this->guardRow(
                Translate::noop('OAuth2 Token Introspection Endpoint Enabled'),
                ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED,
                fn(): Row => new Row(
                    Translate::noop('OAuth2 Token Introspection Endpoint Enabled'),
                    $this->yesNo($this->moduleConfig->getApiOAuth2TokenIntrospectionEndpointEnabled()),
                    ConfigOverviewValueTypeEnum::Text,
                    ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED,
                ),
            ),
            $this->guardRow(
                Translate::noop('Token Introspection Resource Servers'),
                ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RESOURCE_SERVER_CLIENT_IDS,
                function (): Row {
                    $resourceServers = $this->moduleConfig
                        ->getApiOAuth2TokenIntrospectionResourceServerClientIds();

                    return new Row(
                        Translate::noop('Token Introspection Resource Servers'),
                        $resourceServers,
                        ConfigOverviewValueTypeEnum::StringList,
                        ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RESOURCE_SERVER_CLIENT_IDS,
                        $resourceServers === [] ?
                        Translate::noop(
                            'None, so a client authenticating at the introspection endpoint is only ' .
                            'told about tokens issued to itself. API tokens and administrators are ' .
                            'unaffected.',
                        ) :
                        Translate::noop(
                            'These clients may introspect tokens issued to any client, and not only ' .
                            'their own, so each one can read every other client\'s token subject and ' .
                            'scopes.',
                        ),
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('API Tokens'),
                ModuleConfig::OPTION_API_TOKENS,
                fn(): Row => $this->buildSecretCountRow(
                    Translate::noop('API Tokens'),
                    count($this->moduleConfig->getApiTokens() ?? []),
                    ModuleConfig::OPTION_API_TOKENS,
                    Translate::noop('The tokens themselves are secrets and are never shown here.'),
                    ($isApiEnabled && $apiTokenCount === 0) ? Translate::noop(
                        'The API is enabled, but no API tokens are configured, so it can only be ' .
                        'used by a logged in SimpleSAMLphp administrator. Token authenticated ' .
                        'callers will be rejected.',
                    ) : null,
                ),
            ),
        ];

        if ($isApiEnabled && $isIntrospectionEnabled) {
            $rows[] = new Row(
                Translate::noop('Token Introspection Endpoint'),
                $this->routes->urlApiOAuth2TokenIntrospection(),
                ConfigOverviewValueTypeEnum::Url,
            );
        }

        return new Section(Translate::noop('API'), 'api', ...$rows);
    }


    /**
     * Human readable description of the Dynamic Client Registration access-control mode.
     */
    protected function describeRegistrationAuth(DcrRegistrationAuthEnum $registrationAuth): string
    {
        return match ($registrationAuth) {
            DcrRegistrationAuthEnum::Open => Translate::noop('Open (no authentication required)'),
            DcrRegistrationAuthEnum::InitialAccessToken => Translate::noop('Initial Access Token required'),
        };
    }


    /**
     * Render the configured authproc filters as a list, tolerating both the array form (with a
     * 'class' key) and the plain string shorthand.
     *
     * The list is sorted by priority, since that, and not the order of declaration, is the order
     * SimpleSAMLphp's ProcessingChain::addFilters() runs them in.
     *
     * @return string[]
     * @throws \Exception
     */
    protected function buildAuthProcFilterList(): array
    {
        $filters = [];

        $authProcFilters = $this->moduleConfig->getAuthProcFilters();
        ksort($authProcFilters);

        /** @var mixed $authProcFilter */
        foreach ($authProcFilters as $priority => $authProcFilter) {
            if (is_string($authProcFilter)) {
                $filters[] = $priority . ': ' . $authProcFilter;
                continue;
            }

            if (is_array($authProcFilter) && isset($authProcFilter['class']) && is_string($authProcFilter['class'])) {
                $filters[] = $priority . ': ' . $authProcFilter['class'];
                continue;
            }

            $filters[] = $priority . ': ' . Translate::noop('[filter class not set]');
        }

        return $filters;
    }


    /**
     * Prepare scope definitions for display, including where each scope comes from and the options
     * which affect how its claims are emitted.
     *
     * @return array<array{
     *     name: string,
     *     description: string,
     *     origin: string,
     *     claims: string[],
     *     claimNamePrefix: ?string,
     *     areMultipleClaimValuesAllowed: bool
     * }>
     * @throws \Exception
     */
    protected function buildScopeList(): array
    {
        $customScopeNames = array_keys($this->moduleConfig->getPrivateScopes());
        $vciScopeNames = array_keys($this->moduleConfig->getVciScopes());

        $scopes = [];

        /** @var mixed $scopeConfig */
        foreach ($this->moduleConfig->getScopes() as $scopeName => $scopeConfig) {
            $scopeName = (string)$scopeName;
            $scopeConfig = is_array($scopeConfig) ? $scopeConfig : [];

            // Mirrors the merge order in ModuleConfig::getScopes(), where Verifiable Credential
            // scopes are merged last and therefore win a name collision with a custom scope.
            if (in_array($scopeName, $vciScopeNames, true)) {
                $origin = Translate::noop('Verifiable Credential');
            } elseif (in_array($scopeName, $customScopeNames, true)) {
                $origin = Translate::noop('Custom');
            } else {
                $origin = Translate::noop('Standard');
            }

            /** @var mixed $description */
            $description = $scopeConfig[self::SCOPE_KEY_DESCRIPTION] ?? '';
            /** @var mixed $claims */
            $claims = $scopeConfig[self::SCOPE_KEY_CLAIMS] ?? [];
            /** @var mixed $claimNamePrefix */
            $claimNamePrefix = $scopeConfig[self::SCOPE_KEY_CLAIM_NAME_PREFIX] ?? null;

            $scopes[] = [
                'name' => $scopeName,
                'description' => is_string($description) ? $description : '',
                'origin' => $origin,
                'claims' => is_array($claims) ? array_values(array_filter($claims, 'is_string')) : [],
                'claimNamePrefix' => (is_string($claimNamePrefix) && $claimNamePrefix !== '') ?
                    $claimNamePrefix :
                    null,
                'areMultipleClaimValuesAllowed' =>
                    (bool)($scopeConfig[self::SCOPE_KEY_MULTIPLE_CLAIM_VALUES_ALLOWED] ?? false),
            ];
        }

        return $scopes;
    }
}

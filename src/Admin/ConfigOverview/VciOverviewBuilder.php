<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin\ConfigOverview;

use DateInterval;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Codebooks\ConfigOverviewValueTypeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPoolBag;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;
use Stringable;
use Throwable;

/**
 * Builds the sections shown on the OpenID for Verifiable Credential Issuance configuration overview
 * screen.
 *
 * As with the other screens, every row which corresponds to a ModuleConfig::OPTION_* constant records
 * it, so ConfigOptionCoverageTest can assert no option silently goes missing.
 *
 * @see \SimpleSAML\Module\oidc\Admin\ConfigOverview\AbstractOverviewBuilder
 */
class VciOverviewBuilder extends AbstractOverviewBuilder
{
    /** The configured claim path is not among those the credential configuration declares. */
    protected const string REASON_NOT_DECLARED = 'notDeclared';

    /** Declared, but discarded during serialization for this credential format. */
    protected const string REASON_DROPPED_FOR_FORMAT = 'droppedForFormat';

    /**
     * Credential formats CredentialIssuerCredentialController can actually issue. A configuration
     * with any other format, or none, is rejected at issuance time.
     */
    protected const array SUPPORTED_FORMATS = [
        CredentialFormatIdentifiersEnum::JwtVcJson->value,
        CredentialFormatIdentifiersEnum::DcSdJwt->value,
        CredentialFormatIdentifiersEnum::VcSdJwt->value,
    ];

    /**
     * @return \SimpleSAML\Module\oidc\Admin\ConfigOverview\Section[]
     * @throws \Exception
     */
    public function build(): array
    {
        return [
            $this->buildEntitySection(),
            $this->buildEndpointsSection(),
            $this->buildSignatureKeysSection(),
            $this->buildCredentialConfigurationsSection(),
            $this->buildNonRegisteredClientsSection(),
            $this->buildStatusListsSection(),
            $this->buildDurationsSection(),
            $this->buildCredentialOfferSection(),
        ];
    }

    /**
     * Token Status List settings, being what makes issued credentials revocable.
     */
    protected function buildStatusListsSection(): Section
    {
        $isEnabled = false;

        try {
            $isEnabled = $this->moduleConfig->getVciStatusListEnabled();
        } catch (Throwable) {
            // Reported on its own row below, where the option which failed to resolve is named.
        }

        $rows = [
            $this->guardRow(
                Translate::noop('Status Lists Enabled'),
                ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED,
                function (): Row {
                    $enabled = $this->moduleConfig->getVciStatusListEnabled();

                    return new Row(
                        Translate::noop('Status Lists Enabled'),
                        $this->yesNo($enabled),
                        ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED,
                        $enabled ?
                        Translate::noop(
                            'Issued credentials get a Status List entry, so they can be revoked and ' .
                            'suspended.',
                        ) :
                        Translate::noop(
                            'New credentials are issued without a status claim, so they can not be ' .
                            'revoked. Status Lists which already exist keep being served regardless ' .
                            'of this setting, so credentials issued earlier stay verifiable.',
                        ),
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('Status List Key Profile'),
                ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE,
                fn(): Row => new Row(
                    Translate::noop('Status List Key Profile'),
                    $this->moduleConfig->getVciStatusListKeyProfile()->value,
                    ConfigOverviewValueTypeEnum::RawText,
                    ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE,
                    Translate::noop(
                        'How Status List Tokens identify their signing key. Each list records the ' .
                        'profile it was created under, so changing this affects newly created lists ' .
                        'only and never invalidates credentials already issued. A pool may override it.',
                    ),
                ),
            ),
            $this->guardRow(
                Translate::noop('Status List Pools'),
                ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS,
                function () use ($isEnabled): Row {
                    $poolBag = $this->moduleConfig->getVciStatusListPoolBag();

                    if ($poolBag->isEmpty()) {
                        return new Row(
                            Translate::noop('Status List Pools'),
                            Translate::noop('None configured'),
                            ConfigOverviewValueTypeEnum::Text,
                            ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS,
                            Translate::noop(
                                'No credential configuration allocates a Status List entry, so no ' .
                                'issued credential can be revoked.',
                            ),
                        );
                    }

                    return new Row(
                        Translate::noop('Status List Pools'),
                        $this->describeStatusListPools($poolBag),
                        ConfigOverviewValueTypeEnum::Json,
                        ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS,
                        $isEnabled ?
                        Translate::noop(
                            'Credentials of a configuration which is in no pool are issued without a ' .
                            'status claim. Privacy rests on many credentials sharing one list, so ' .
                            'more pools means a smaller group each credential hides in. A pool also ' .
                            'keeps a separate list for credentials which never expire, so giving ' .
                            'every configuration in it a lifetime keeps it to a single list.',
                        ) :
                        Translate::noop(
                            'These pools are inert, since Status Lists are disabled.',
                        ),
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('Status List Requests Per Minute'),
                ModuleConfig::OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE,
                function (): Row {
                    $limit = $this->moduleConfig->getVciStatusListRequestsPerMinute();

                    return new Row(
                        Translate::noop('Status List Requests Per Minute'),
                        $limit > 0 ? (string)$limit : Translate::noop('No limit'),
                        $limit > 0 ? ConfigOverviewValueTypeEnum::RawText : ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE,
                        $limit > 0 ?
                        Translate::noop(
                            'Applied to the address the request appears to come from, which behind a ' .
                            'reverse proxy is the proxy unless it is trusted. Confirm which address ' .
                            'arrives here, since one shared bucket would refuse every client. Needs a ' .
                            'protocol cache; without one nothing is counted.',
                        ) :
                        Translate::noop(
                            'The Status List endpoint accepts any number of requests. It is ' .
                            'unauthenticated and its response can reach a couple of hundred ' .
                            'kilobytes.',
                        ),
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('Credential Status Endpoint Enabled'),
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED,
                function () use ($isEnabled): Row {
                    $isStatusEndpointEnabled = $this->moduleConfig->getApiVciCredentialStatusEndpointEnabled();

                    return new Row(
                        Translate::noop('Credential Status Endpoint Enabled'),
                        $this->yesNo($isStatusEndpointEnabled),
                        ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED,
                        $isStatusEndpointEnabled ?
                        Translate::noop(
                            'Issued credentials can be revoked, suspended and reinstated over the ' .
                            'network. This endpoint takes a bearer token from the Authorization ' .
                            'header only, never an administrator session, and every change made ' .
                            'through it is recorded against the token which asked for it.',
                        ) :
                        Translate::noop(
                            'Not served, so credential statuses can only be changed from the ' .
                            'administration screens. Also requires the module API to be enabled.',
                        ),
                        ($isStatusEndpointEnabled && !$isEnabled) ? Translate::noop(
                            'Status Lists are disabled, so credentials being issued now have no ' .
                            'entry to change. Ones issued while they were enabled can still be ' .
                            'revoked through this endpoint.',
                        ) : null,
                    );
                },
            ),
            $this->guardRow(
                Translate::noop('Status List Retirement Grace'),
                ModuleConfig::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
                fn(): Row => new Row(
                    Translate::noop('Status List Retirement Grace'),
                    $this->dateIntervalFormatter->toDurationSpec(
                        $this->moduleConfig->getVciStatusListRetirementGrace(),
                    ),
                    ConfigOverviewValueTypeEnum::RawText,
                    ModuleConfig::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
                    Translate::noop(
                        'How long a list is left alone before it may be retired, counted both from ' .
                        'when it stopped accepting credentials and from when the last credential in ' .
                        'it expired, and once more before its entries are removed. Retiring makes a ' .
                        'URI written into real credentials answer 404, so this is the margin for ' .
                        'anything still working from a cached response, and for an issuance which ' .
                        'was under way when the list closed. Runs from the cron hook.',
                    ),
                ),
            ),
            $this->guardRow(
                Translate::noop('Status Audit Retention'),
                ModuleConfig::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION,
                function (): Row {
                    $retention = $this->moduleConfig->getVciStatusListAuditRetention();

                    return new Row(
                        Translate::noop('Status Audit Retention'),
                        $retention instanceof DateInterval ?
                        $this->dateIntervalFormatter->toDurationSpec($retention) :
                        Translate::noop('Kept indefinitely'),
                        $retention instanceof DateInterval ?
                        ConfigOverviewValueTypeEnum::RawText :
                        ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION,
                        $retention instanceof DateInterval ?
                        Translate::noop(
                            'Rows recording who asked for which credential status change are pruned ' .
                            'once they reach this age. Pruning runs from the cron hook.',
                        ) :
                        Translate::noop(
                            'The record of who asked for which credential status change is kept for ' .
                            'good. Credentials appear in it only as a hash, but the actor is ' .
                            'recorded as given, which where the admin authentication source ' .
                            'releases an identifier is a person.',
                        ),
                    );
                },
            ),
        ];

        return new Section(Translate::noop('Status Lists'), 'statusLists', ...$rows);
    }

    /**
     * @return array<string,array<string,mixed>>
     */
    protected function describeStatusListPools(StatusListPoolBag $poolBag): array
    {
        $described = [];

        foreach ($poolBag->getAll() as $poolId => $pool) {
            $described[$poolId] = [
                StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => $pool->getCredentialConfigurationIds(),
                StatusListPool::KEY_BITS => $pool->getBits(),
                StatusListPool::KEY_CAPACITY => $pool->getCapacity(),
                StatusListPool::KEY_ALLOWED_STATUSES => array_map(
                    static fn(StatusTypeEnum $status): string => $status->name,
                    $pool->getAllowedStatuses(),
                ),
                StatusListPool::KEY_TTL => $this->dateIntervalFormatter->toDurationSpec($pool->getTtl()),
                StatusListPool::KEY_TOKEN_VALIDITY => $this->dateIntervalFormatter
                    ->toDurationSpec($pool->getTokenValidity()),
                StatusListPool::KEY_REFRESH_INTERVAL => $this->dateIntervalFormatter
                    ->toDurationSpec($pool->getRefreshInterval()),
                StatusListPool::KEY_KEY_PROFILE => $pool->getKeyProfile()->value,
            ];
        }

        return $described;
    }

    /**
     * @throws \Exception
     */
    protected function buildEntitySection(): Section
    {
        return new Section(
            Translate::noop('Entity'),
            'entity',
            $this->guardRow(
                Translate::noop('Verifiable Credential Issuance Enabled'),
                ModuleConfig::OPTION_VCI_ENABLED,
                function (): Row {
                    $isEnabled = $this->moduleConfig->getVciEnabled();

                    return new Row(
                        Translate::noop('Verifiable Credential Issuance Enabled'),
                        $this->yesNo($isEnabled),
                        ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_VCI_ENABLED,
                        $isEnabled ? null : Translate::noop(
                            'All Verifiable Credential capabilities are off, and the credential ' .
                            'issuer endpoints are not served. The settings below are inert until ' .
                            'this is enabled.',
                        ),
                    );
                },
            ),
            $this->buildIssuerRow(
                Translate::noop('Also the Credential Issuer identifier.'),
                Translate::noop(
                    'Not explicitly configured, so it is derived from the current HTTP host. Since ' .
                    'this is also the Credential Issuer identifier, it can change depending on how ' .
                    'the OP is reached, which breaks already issued credential offers.',
                ),
            ),
            new Row(
                Translate::noop('Credential Issuer Configuration URL'),
                $this->routes->urlCredentialIssuerConfiguration(),
                ConfigOverviewValueTypeEnum::Url,
            ),
            new Row(
                Translate::noop('JWT VC Issuer Configuration URL'),
                $this->routes->urlJwtVcIssuerConfiguration(),
                ConfigOverviewValueTypeEnum::Url,
            ),
        );
    }

    /**
     * @throws \Exception
     */
    protected function buildEndpointsSection(): Section
    {
        // A malformed switch is reported on its own row in the sections which own it; here the
        // conservative reading is simply that the capability is off.
        try {
            $isEnabled = $this->moduleConfig->getVciEnabled();
        } catch (Throwable) {
            $isEnabled = false;
        }

        // VciCredentialOfferApiController requires all three: the API, the endpoint, and the VCI
        // master switch.
        try {
            $isOfferEndpointServed = $isEnabled &&
            $this->moduleConfig->getApiEnabled() &&
            $this->moduleConfig->getApiVciCredentialOfferEndpointEnabled();
        } catch (Throwable) {
            $isOfferEndpointServed = false;
        }

        // Both CredentialIssuerCredentialController and NonceController refuse to construct while the
        // master switch is off, so neither endpoint is reachable.
        $disabledNote = $isEnabled ?
        null :
        Translate::noop('Not served, since Verifiable Credential Issuance is disabled.');

        $rows = [
            new Row(
                Translate::noop('Credential'),
                $this->routes->urlCredentialIssuerCredential(),
                ConfigOverviewValueTypeEnum::Url,
                null,
                $disabledNote,
            ),
            new Row(
                Translate::noop('Nonce'),
                $this->routes->urlCredentialIssuerNonce(),
                ConfigOverviewValueTypeEnum::Url,
                null,
                $disabledNote,
            ),
        ];

        if ($isOfferEndpointServed) {
            $rows[] = new Row(
                Translate::noop('Credential Offer (API)'),
                $this->routes->urlApiVciCredentialOffer(),
                ConfigOverviewValueTypeEnum::Url,
            );
        }

        // Deliberately not conditioned on the issuance switch, because the controller is not either:
        // credentials already in wallets stay revocable while issuance is off. Requiring it here
        // would hide the URL of an endpoint which is live, and hide it precisely during the incident
        // that made someone turn issuance off.
        try {
            $isStatusEndpointServed = $this->moduleConfig->getApiEnabled() &&
            $this->moduleConfig->getApiVciCredentialStatusEndpointEnabled();
        } catch (Throwable) {
            $isStatusEndpointServed = false;
        }

        if ($isStatusEndpointServed) {
            $rows[] = new Row(
                Translate::noop('Credential Status (API)'),
                $this->routes->urlApiVciCredentialStatus(),
                ConfigOverviewValueTypeEnum::Url,
            );
        }

        return new Section(Translate::noop('Endpoints'), 'endpoints', ...$rows);
    }

    protected function buildSignatureKeysSection(): Section
    {
        $keyPairBag = null;
        $error = null;

        try {
            $keyPairBag = $this->moduleConfig->getVciSignatureKeyPairBag();
        } catch (Throwable $exception) {
            $error = $this->describeResolutionError($exception, ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS);
        }

        return new Section(
            Translate::noop('Signature algorithms and public keys'),
            'signature-keys',
            new Row(
                Translate::noop('Verifiable Credential Signature Key Pairs'),
                $keyPairBag,
                ConfigOverviewValueTypeEnum::SignatureKeyPairs,
                ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS,
                Translate::noop(
                    'Used to sign issued credentials, their Status List Tokens and the nonces wallets ' .
                    'prove possession against. Only the first pair, marked as the default, signs; the ' .
                    'others are published so that what they signed stays verifiable. These keys should ' .
                    'not be the same as the protocol (Connect) signing keys.',
                ),
                $error,
            ),
        );
    }

    /**
     * @throws \Exception
     */
    protected function buildCredentialConfigurationsSection(): Section
    {
        // These two options are resolved once, each under its own guard, and then handed to the
        // list builder. Resolving them inside it would let one malformed option empty the whole
        // credential configuration list and pin the blame on the wrong setting.
        $jsonLdContexts = [];
        $jsonLdContextError = null;

        try {
            $jsonLdContexts = $this->moduleConfig->getVciCredentialJsonLdContext();
        } catch (Throwable $exception) {
            $jsonLdContextError = $this->describeResolutionError(
                $exception,
                ModuleConfig::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT,
            );
        }

        $attributeMap = [];
        $attributeMapError = null;

        try {
            $attributeMap = $this->moduleConfig->getVciUserAttributeToCredentialClaimPathMap();
        } catch (Throwable $exception) {
            $attributeMapError = $this->describeResolutionError(
                $exception,
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP,
            );
        }

        $credentialConfigurations = [];
        $error = null;

        try {
            $credentialConfigurations = $this->buildCredentialConfigurationList(
                $this->findIdsWithJsonLdContext($jsonLdContexts),
                $attributeMap,
            );
        } catch (Throwable $exception) {
            $error = $this->describeResolutionError(
                $exception,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
            );
        }

        // Only entries which are arrays are usable: getVciCredentialJsonLdContextFor() treats
        // anything else as absent, so its document endpoint would return a 404.
        $jsonLdContextCount = count($this->findIdsWithJsonLdContext($jsonLdContexts));

        if (is_null($error)) {
            $hasIneffectiveMapping = $this->hasMappingFlag($credentialConfigurations, 'isEffective', false);
            $hasIgnoredPairs = $this->hasMappingFlag($credentialConfigurations, 'hasIgnoredPairs', true);

            // Deliberately generic about why a mapping is ineffective, since there are two distinct
            // reasons and each one is named on the mapping itself.
            $error = match (true) {
                $this->hasUnsupportedFormat($credentialConfigurations) => Translate::noop(
                    'At least one credential configuration has a missing or unsupported format, so ' .
                    'it cannot issue credentials at all. Supported formats are jwt_vc_json, ' .
                    'dc+sd-jwt and vc+sd-jwt.',
                ),
                $hasIneffectiveMapping && $hasIgnoredPairs => Translate::noop(
                    'At least one attribute mapping never reaches the credential, and at least one ' .
                    'map entry holds more than one attribute, of which issuance reads only the ' .
                    'first. The affected mappings are marked above.',
                ),
                $hasIneffectiveMapping => Translate::noop(
                    'At least one attribute mapping never reaches the credential. The affected ' .
                    'mappings are marked above with the reason.',
                ),
                $hasIgnoredPairs => Translate::noop(
                    'At least one attribute map entry holds more than one attribute. Issuance reads ' .
                    'only the first pair of an entry, so the rest are ignored. Give each attribute ' .
                    'its own entry.',
                ),
                default => null,
            };
        }

        return new Section(
            Translate::noop('Credential configurations'),
            'credential-configurations',
            new Row(
                Translate::noop('Supported Credential Configurations'),
                $credentialConfigurations,
                ConfigOverviewValueTypeEnum::CredentialConfigurations,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
                is_null($error) ? Translate::noop(
                    'Published as \'credential_configurations_supported\' in the Credential Issuer ' .
                    'metadata. Each configuration also becomes a requestable scope of the same name.',
                ) : null,
                $error,
            ),
            new Row(
                Translate::noop('Attribute to Claim Path Mappings'),
                $attributeMap,
                ConfigOverviewValueTypeEnum::Json,
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP,
                is_null($attributeMapError) ? Translate::noop(
                    'Which released user attribute populates which claim path, per credential ' .
                    'configuration. The effective mappings are also listed per configuration above.',
                ) : null,
                $attributeMapError,
            ),
            $this->buildSecretCountRow(
                Translate::noop('JSON-LD Context Documents'),
                $jsonLdContextCount,
                ModuleConfig::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT,
                is_null($jsonLdContextError) ? Translate::noop(
                    'Served per credential configuration, for formats which reference a JSON-LD ' .
                    'context. The document URL is listed with its configuration above.',
                ) : null,
                $jsonLdContextError,
            ),
        );
    }

    /**
     * @throws \Exception
     */
    protected function buildNonRegisteredClientsSection(): Section
    {
        $areAllowed = false;
        $areAllowedError = null;

        try {
            $areAllowed = $this->moduleConfig->getVciAllowNonRegisteredClients();
        } catch (Throwable $exception) {
            $areAllowedError = $this->describeResolutionError(
                $exception,
                ModuleConfig::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS,
            );
        }

        $allowedPrefixes = [];
        $allowedPrefixesError = null;

        try {
            $allowedPrefixes = $this->moduleConfig->getVciAllowedRedirectUriPrefixesForNonRegisteredClients();
        } catch (Throwable $exception) {
            $allowedPrefixesError = $this->describeResolutionError(
                $exception,
                ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS,
            );
        }

        // ClientRedirectUriRule casts every configured entry with (string) before calling
        // str_starts_with(), so the same normalization is applied here rather than dropping entries
        // which are not strings. A configured null becomes an empty prefix, and every redirect URI
        // starts with an empty string.
        $normalizedPrefixes = [];
        $hasEmptyPrefix = false;
        $hasNonStringPrefix = false;
        $hasUncastablePrefix = false;

        /** @var mixed $prefix */
        foreach ($allowedPrefixes as $prefix) {
            $normalizedPrefix = $this->normalizeRedirectUriPrefix($prefix);

            if (is_null($normalizedPrefix)) {
                $hasUncastablePrefix = true;
                continue;
            }

            $normalizedPrefixes[] = $normalizedPrefix;

            if (!is_string($prefix)) {
                $hasNonStringPrefix = true;
            }

            if ($normalizedPrefix === '') {
                $hasEmptyPrefix = true;
            }
        }

        $prefixesWarning = match (true) {
            $areAllowed && $hasEmptyPrefix => Translate::noop(
                'One of the configured prefixes is empty, which every redirect URI starts with, so ' .
                'a non-registered client can be redirected anywhere. Note that a configured null ' .
                'becomes an empty prefix.',
            ),
            $areAllowed && $hasUncastablePrefix => Translate::noop(
                'One of the configured prefixes cannot be turned into a string at all, so the ' .
                'redirect URI check will fail rather than match.',
            ),
            $areAllowed && $hasNonStringPrefix => Translate::noop(
                'One of the configured prefixes is not a string. It is shown above as the literal ' .
                'prefix it becomes at runtime, which is unlikely to be what was intended.',
            ),
            $areAllowed && $normalizedPrefixes === [] => Translate::noop(
                'Non-registered clients are allowed, but no redirect URI prefix is configured, ' .
                'so every such authorization request will be rejected.',
            ),
            default => null,
        };

        return new Section(
            Translate::noop('Non-registered clients'),
            'non-registered-clients',
            new Row(
                Translate::noop('Allow Non-registered Clients'),
                $this->yesNo($areAllowed),
                ConfigOverviewValueTypeEnum::Text,
                ModuleConfig::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS,
                is_null($areAllowedError) ? ($areAllowed ? Translate::noop(
                    'A wallet which is not registered as a client may request credentials. The ' .
                    'redirect URI prefix allowlist below is the only control on where it is sent back.',
                ) : Translate::noop('Only registered clients may request credentials.')) : null,
                $areAllowedError,
            ),
            new Row(
                Translate::noop('Allowed Redirect URI Prefixes'),
                $normalizedPrefixes,
                ConfigOverviewValueTypeEnum::StringList,
                ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS,
                is_null($allowedPrefixesError) ? Translate::noop(
                    'A redirect URI from a non-registered client must start with one of these. Keep ' .
                    'them specific: a loose prefix defeats the check.',
                ) : null,
                $allowedPrefixesError ?? $prefixesWarning,
            ),
        );
    }

    /**
     * @throws \Exception
     */
    protected function buildDurationsSection(): Section
    {
        $isIssuerStateTtlConfigured = $this->moduleConfig->config()
            ->hasValue(ModuleConfig::OPTION_VCI_ISSUER_STATE_TTL);
        $isNonceTtlConfigured = $this->moduleConfig->config()->hasValue(ModuleConfig::OPTION_VCI_NONCE_TTL);

        // Both getters hand the configured value to DateInterval, which throws on a bad spec.
        return new Section(
            Translate::noop('Durations'),
            'durations',
            $this->guardRow(
                Translate::noop('Issuer State TTL'),
                ModuleConfig::OPTION_VCI_ISSUER_STATE_TTL,
                fn(): Row => $this->buildDurationRow(
                    Translate::noop('Issuer State TTL'),
                    $this->moduleConfig->getVciIssuerStateDuration(),
                    ModuleConfig::OPTION_VCI_ISSUER_STATE_TTL,
                    $isIssuerStateTtlConfigured ?
                    Translate::noop('How long an issuer state from a credential offer stays usable.') :
                    Translate::noop('Not configured, so this falls back to the Authorization Code TTL.'),
                ),
            ),
            $this->guardRow(
                Translate::noop('Nonce TTL'),
                ModuleConfig::OPTION_VCI_NONCE_TTL,
                fn(): Row => $this->buildDurationRow(
                    Translate::noop('Nonce TTL'),
                    $this->moduleConfig->getVciNonceTtl(),
                    ModuleConfig::OPTION_VCI_NONCE_TTL,
                    $isNonceTtlConfigured ?
                    Translate::noop('How long a proof-of-possession nonce stays valid.') :
                    Translate::noop(
                        'Not configured, so this falls back to 5 minutes. Used for ' .
                        'proof-of-possession nonces.',
                    ),
                ),
            ),
            $this->guardRow(
                Translate::noop('Credential Lifetimes'),
                ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS,
                function (): Row {
                    $ttls = $this->moduleConfig->getVciCredentialTtls();

                    if ($ttls === []) {
                        return new Row(
                            Translate::noop('Credential Lifetimes'),
                            Translate::noop('None configured'),
                            ConfigOverviewValueTypeEnum::Text,
                            ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS,
                            Translate::noop(
                                'Issued credentials never expire, which is the long standing default. ' .
                                'Such credentials are allocated into Status Lists of their own, so ' .
                                'they hold up no other credential, but those lists can never be ' .
                                'retired and their storage is kept for good.',
                            ),
                        );
                    }

                    return new Row(
                        Translate::noop('Credential Lifetimes'),
                        array_map(
                            fn(DateInterval $ttl): array => [$this->dateIntervalFormatter->toDurationSpec($ttl)],
                            $ttls,
                        ),
                        ConfigOverviewValueTypeEnum::StringMap,
                        ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS,
                        Translate::noop(
                            'How long a credential of each configuration stays valid. Configurations ' .
                            'which are not listed issue credentials which never expire.',
                        ),
                    );
                },
            ),
        );
    }

    /**
     * @throws \Exception
     */
    protected function buildCredentialOfferSection(): Section
    {
        // Resolved separately, so that a malformed api_enabled is not reported as a failure of the
        // credential offer endpoint option, and vice versa.
        try {
            $isApiEnabled = $this->moduleConfig->getApiEnabled();
        } catch (Throwable) {
            // Reported on the protocol screen, which owns this option. Here the conservative
            // reading is that the API is off, which is what the endpoint warning below needs.
            $isApiEnabled = false;
        }

        $isOfferEndpointEnabled = false;
        $offerEndpointError = null;

        try {
            $isOfferEndpointEnabled = $this->moduleConfig->getApiVciCredentialOfferEndpointEnabled();
        } catch (Throwable $exception) {
            $offerEndpointError = $this->describeResolutionError(
                $exception,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED,
            );
        }

        $defaultEmailAttribute = null;
        $defaultEmailAttributeError = null;

        try {
            $defaultEmailAttribute = $this->moduleConfig->getDefaultUsersEmailAttributeName();
        } catch (Throwable $exception) {
            $defaultEmailAttributeError = $this->describeResolutionError(
                $exception,
                ModuleConfig::OPTION_DEFAULT_USERS_EMAIL_ATTRIBUTE_NAME,
            );
        }

        $configuredEmailMap = [];
        // A resolution failure suppresses the note, since nothing could be read. An ignored override
        // is different: the option is readable and the note still describes it correctly.
        $emailMapResolutionError = null;
        $emailMapWarning = null;

        try {
            $configuredEmailMap = $this->moduleConfig->getAuthSourcesToUsersEmailAttributeMap();
        } catch (Throwable $exception) {
            $emailMapResolutionError = $this->describeResolutionError(
                $exception,
                ModuleConfig::OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP,
            );
            $emailMapWarning = $emailMapResolutionError;
        }

        if (is_null($emailMapResolutionError) && $this->hasIgnoredEmailAttributeOverride($configuredEmailMap)) {
            $emailMapWarning = Translate::noop(
                'At least one configured override is not a string, so it is not an override at all: ' .
                'that authentication source falls back to the default attribute above. Such entries ' .
                'are not listed here.',
            );
        }

        return new Section(
            Translate::noop('Credential offers'),
            'credential-offers',
            new Row(
                Translate::noop('Credential Offer Endpoint Enabled'),
                $this->yesNo($isOfferEndpointEnabled),
                ConfigOverviewValueTypeEnum::Text,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED,
                is_null($offerEndpointError) ? Translate::noop(
                    'Lets a credential offer be created through the module API, for example to send ' .
                    'it to a user by email.',
                ) : null,
                $offerEndpointError ?? (($isOfferEndpointEnabled && !$isApiEnabled) ? Translate::noop(
                    'The module API itself is disabled, so this endpoint is not served. Enable the ' .
                    'API on the protocol settings screen.',
                ) : null),
            ),
            new Row(
                Translate::noop('Default User Email Attribute'),
                $defaultEmailAttribute ?? Translate::noop('N/A'),
                is_null($defaultEmailAttribute) ?
                ConfigOverviewValueTypeEnum::Text :
                ConfigOverviewValueTypeEnum::RawText,
                ModuleConfig::OPTION_DEFAULT_USERS_EMAIL_ATTRIBUTE_NAME,
                is_null($defaultEmailAttributeError) ?
                Translate::noop('Attribute read to find the address a credential offer is sent to.') :
                null,
                $defaultEmailAttributeError,
            ),
            new Row(
                Translate::noop('Authentication Sources to Email Attribute Map'),
                $this->buildEmailAttributeMap($configuredEmailMap),
                ConfigOverviewValueTypeEnum::StringMap,
                ModuleConfig::OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP,
                is_null($emailMapResolutionError) ? Translate::noop(
                    'Overrides the default per authentication source. Sources which are not listed ' .
                    'use the default above.',
                ) : null,
                $emailMapWarning,
            ),
        );
    }

    /**
     * Prepare the supported credential configurations for display, pulling together the pieces which
     * are otherwise spread over several config options.
     *
     * @return array<array{
     *     id: string,
     *     format: ?string,
     *     isFormatSupported: bool,
     *     scope: ?string,
     *     displayNames: string[],
     *     claimPaths: string[],
     *     attributeMappings: array<array{
     *         attribute: string,
     *         path: string,
     *         ineffectiveReason: ?string,
     *         isEffective: bool,
     *         hasIgnoredPairs: bool
     *     }>,
     *     jsonLdContextUrl: ?string
     * }>
     * @throws \Exception
     */
    protected function buildCredentialConfigurationList(array $idsWithJsonLdContext, array $attributeMap): array
    {
        $configurations = [];

        foreach ($this->moduleConfig->getVciCredentialConfigurationIdsSupported() as $id) {
            // Throws for a non-array entry, which the caller turns into a row warning.
            $configuration = $this->moduleConfig->getVciCredentialConfiguration($id) ?? [];

            /** @var mixed $format */
            $format = $configuration[ClaimsEnum::Format->value] ?? null;
            /** @var mixed $scope */
            $scope = $configuration[ClaimsEnum::Scope->value] ?? null;

            $validClaimPaths = $this->moduleConfig->getVciValidCredentialClaimPathsFor($id);

            $format = is_string($format) ? $format : null;

            $configurations[] = [
                'id' => $id,
                'format' => $format,
                'isFormatSupported' => in_array($format, self::SUPPORTED_FORMATS, true),
                'scope' => is_string($scope) ? $scope : null,
                'displayNames' => $this->buildDisplayNames($configuration),
                'claimPaths' => $this->buildClaimPaths($validClaimPaths),
                'attributeMappings' => $this->buildAttributeMappings(
                    $this->findAttributeMappingsFor($attributeMap, $id),
                    $validClaimPaths,
                    $format,
                ),
                'jsonLdContextUrl' => in_array($id, $idsWithJsonLdContext, true) ?
                    $this->routes->urlCredentialJsonLdContext($id) :
                    null,
            ];
        }

        return $configurations;
    }

    /**
     * Credential configuration IDs which have a usable JSON-LD context document.
     *
     * Mirrors ModuleConfig::getVciCredentialJsonLdContextFor(), which treats a non-array entry as
     * no context at all.
     *
     * @return string[]
     */
    protected function findIdsWithJsonLdContext(array $jsonLdContexts): array
    {
        $ids = [];

        /** @var mixed $context */
        foreach ($jsonLdContexts as $id => $context) {
            if (is_array($context)) {
                $ids[] = (string)$id;
            }
        }

        return $ids;
    }

    /**
     * Configured attribute mappings for one credential configuration.
     *
     * Mirrors ModuleConfig::getVciUserAttributeToCredentialClaimPathMapFor().
     */
    protected function findAttributeMappingsFor(array $attributeMap, string $credentialConfigurationId): array
    {
        /** @var mixed $mappings */
        $mappings = $attributeMap[$credentialConfigurationId] ?? [];

        return is_array($mappings) ? $mappings : [];
    }

    /**
     * Normalize a configured redirect URI prefix exactly the way ClientRedirectUriRule does, that
     * is, with a plain (string) cast.
     *
     * Returns null only when no cast is possible, in which case the runtime would raise an error
     * rather than match anything.
     */
    protected function normalizeRedirectUriPrefix(mixed $prefix): ?string
    {
        if (is_scalar($prefix) || is_null($prefix)) {
            return (string)$prefix;
        }

        if (is_array($prefix)) {
            // What (string) yields for an array, after emitting a PHP warning.
            return 'Array';
        }

        if ($prefix instanceof Stringable) {
            try {
                return (string)$prefix;
            } catch (Throwable) {
                // A __toString() which throws would take the screen down, and at runtime it would
                // break the redirect URI check just the same.
                return null;
            }
        }

        return null;
    }

    /**
     * Whether any credential configuration declares a format which cannot be issued.
     */
    protected function hasUnsupportedFormat(array $credentialConfigurations): bool
    {
        /** @var mixed $configuration */
        foreach ($credentialConfigurations as $configuration) {
            if (is_array($configuration) && ($configuration['isFormatSupported'] ?? true) === false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether any credential configuration carries a mapping whose given flag has the given value.
     */
    protected function hasMappingFlag(array $credentialConfigurations, string $flag, bool $value): bool
    {
        /** @var mixed $configuration */
        foreach ($credentialConfigurations as $configuration) {
            if (!is_array($configuration) || !is_array($configuration['attributeMappings'] ?? null)) {
                continue;
            }

            /** @var mixed $mapping */
            foreach ($configuration['attributeMappings'] as $mapping) {
                if (is_array($mapping) && ($mapping[$flag] ?? null) === $value) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Display names from the credential metadata, which may carry one entry per locale.
     *
     * @return string[]
     */
    protected function buildDisplayNames(array $configuration): array
    {
        /** @psalm-suppress MixedArrayAccess */
        $display = $configuration[ClaimsEnum::CredentialMetadata->value][ClaimsEnum::Display->value] ?? null;

        if (!is_array($display)) {
            return [];
        }

        $names = [];

        /** @var mixed $displayEntry */
        foreach ($display as $displayEntry) {
            if (!is_array($displayEntry)) {
                continue;
            }

            /** @var mixed $name */
            $name = $displayEntry[ClaimsEnum::Name->value] ?? null;

            if (is_string($name) && !in_array($name, $names, true)) {
                $names[] = $name;
            }
        }

        return $names;
    }

    /**
     * Claim paths declared by a credential configuration, rendered in dotted form.
     *
     * @return string[]
     */
    protected function buildClaimPaths(array $validClaimPaths): array
    {
        $paths = [];

        /** @var mixed $path */
        foreach ($validClaimPaths as $path) {
            if (!is_array($path)) {
                continue;
            }

            $paths[] = $this->renderClaimPath($path);
        }

        return $paths;
    }

    /**
     * Render a declared claim path, in dotted form. Segments which are not scalar are skipped, since
     * they cannot be part of a usable path.
     *
     * Declared paths are shown as configured, because ModuleConfig hands them to issuance unchanged
     * and issuance matches a mapping against them verbatim.
     */
    protected function renderClaimPath(array $path): string
    {
        $segments = [];

        /** @var mixed $segment */
        foreach ($path as $segment) {
            if (is_scalar($segment)) {
                $segments[] = (string)$segment;
            }
        }

        return implode('.', $segments);
    }

    /**
     * Render the claim path a mapping actually writes to.
     *
     * Unlike a declared path, a mapping path is filtered down to its string segments before issuance
     * writes at it, so ['credentialSubject', 0, 'mail'] populates 'credentialSubject.mail'. Showing
     * the configured segments verbatim would name a path the issued credential never has.
     *
     * For 'vc+sd-jwt' there is a further step: the controller takes the last segment as the claim
     * name and, if the remaining parent path does not already mention 'credentialSubject', roots it
     * there. A configured ['mail'] therefore discloses at 'credentialSubject.mail'. The other formats
     * use the filtered path as it stands.
     */
    protected function renderEffectiveClaimPath(array $path, ?string $format): string
    {
        $segments = array_values(array_filter($path, 'is_string'));

        if ($format === CredentialFormatIdentifiersEnum::VcSdJwt->value) {
            $claimName = array_pop($segments);

            // A path with no string segments cannot yield a claim name, and issuance abandons it.
            if (is_string($claimName)) {
                if (!in_array(ClaimsEnum::Credential_Subject->value, $segments, true)) {
                    array_unshift($segments, ClaimsEnum::Credential_Subject->value);
                }

                $segments[] = $claimName;
            }
        }

        return implode('.', $segments);
    }

    /**
     * Effective user attribute to claim path mappings for one credential configuration.
     *
     * The option holds a list of single-entry maps, each being attribute name to path segments.
     *
     * @return array<array{
     *     attribute: string,
     *     path: string,
     *     ineffectiveReason: ?string,
     *     isEffective: bool,
     *     hasIgnoredPairs: bool
     * }>
     */
    protected function buildAttributeMappings(
        array $configuredMappings,
        array $validClaimPaths,
        ?string $format,
    ): array {
        $mappings = [];

        /** @var mixed $mapping */
        foreach ($configuredMappings as $mapping) {
            if (!is_array($mapping)) {
                continue;
            }

            // Mirrors CredentialIssuerCredentialController, which reads only key()/current() of a
            // map entry, so any further pair in the same entry is ignored during issuance. It also
            // requires the attribute name to be a string.
            $attribute = key($mapping);
            /** @var mixed $path */
            $path = current($mapping);

            if (!is_string($attribute)) {
                continue;
            }

            $mappings[] = [
                'attribute' => $attribute,
                'path' => match (true) {
                    is_array($path) => $this->renderEffectiveClaimPath($path, $format),
                    is_scalar($path) => (string)$path,
                    default => '',
                },
                'ineffectiveReason' => $ineffectiveReason =
                    $this->findIneffectiveMappingReason($path, $validClaimPaths, $format),
                'isEffective' => is_null($ineffectiveReason),
                'hasIgnoredPairs' => count($mapping) > 1,
            ];
        }

        return $mappings;
    }

    /**
     * Whether a mapping will actually be applied during issuance.
     *
     * Mirrors CredentialIssuerCredentialController: the configured path must be an array, it is
     * filtered down to its string segments, and it must appear among the claim paths the credential
     * configuration declares. A mapping which fails this is skipped, so listing it as effective
     * would promise an attribute that never reaches the credential.
     *
     * There is a second, format specific rule. For 'jwt_vc_json' the controller writes the value at
     * the configured path but then serializes only the 'credentialSubject' branch, so a path which
     * is not rooted there is written and immediately dropped. The SD-JWT formats do not have this
     * problem: 'dc+sd-jwt' uses the path as-is, and 'vc+sd-jwt' prepends 'credentialSubject' itself.
     *
     * @param mixed $path
     * @return ?string One of the REASON_* constants, or null when the mapping does take effect.
     */
    protected function findIneffectiveMappingReason(mixed $path, array $validClaimPaths, ?string $format): ?string
    {
        if (!is_array($path)) {
            return self::REASON_NOT_DECLARED;
        }

        $stringSegments = array_filter($path, 'is_string');

        if (!in_array($stringSegments, $validClaimPaths)) {
            return self::REASON_NOT_DECLARED;
        }

        if (
            $format === CredentialFormatIdentifiersEnum::JwtVcJson->value &&
            reset($stringSegments) !== ClaimsEnum::Credential_Subject->value
        ) {
            return self::REASON_DROPPED_FOR_FORMAT;
        }

        return null;
    }

    /**
     * Present the auth source to email attribute map in the shape the StringMap rendering expects.
     *
     * @return array<string, string[]>
     * @throws \Exception
     */
    protected function buildEmailAttributeMap(array $configuredMap): array
    {
        $map = [];

        /** @var mixed $attributeName */
        foreach ($configuredMap as $authSourceId => $attributeName) {
            // getUsersEmailAttributeNameForAuthSourceId() only honours a string, and otherwise falls
            // back to the default. A non-string entry is therefore not an override at all, so
            // casting it here would invent one which never takes effect.
            if (!is_string($attributeName)) {
                continue;
            }

            $map[(string)$authSourceId] = [$attributeName];
        }

        return $map;
    }

    /**
     * Whether the configured map holds an entry which the runtime will ignore.
     */
    protected function hasIgnoredEmailAttributeOverride(array $configuredMap): bool
    {
        /** @var mixed $attributeName */
        foreach ($configuredMap as $attributeName) {
            if (!is_string($attributeName)) {
                return true;
            }
        }

        return false;
    }
}

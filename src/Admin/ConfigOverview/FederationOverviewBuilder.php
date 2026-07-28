<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin\ConfigOverview;

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Codebooks\ConfigOverviewValueTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\LimitsEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\TrustMarkStatusEndpointUsagePolicyEnum;
use SimpleSAML\OpenID\Federation\TrustMark;
use Throwable;

/**
 * Builds the sections shown on the OpenID Federation configuration overview screen.
 *
 * Trust Marks are resolved by the controller, which owns the network calls and the error reporting
 * for them, and handed in here already resolved so that this builder stays free of I/O.
 *
 * As with the protocol screen, every row which corresponds to a ModuleConfig::OPTION_* constant
 * records it, so ConfigOptionCoverageTest can assert no option silently goes missing.
 *
 * @see \SimpleSAML\Module\oidc\Admin\ConfigOverview\AbstractOverviewBuilder
 */
class FederationOverviewBuilder extends AbstractOverviewBuilder
{
    /**
     * @param \SimpleSAML\OpenID\Federation\TrustMark[] $trustMarks Already resolved by the caller.
     * @return \SimpleSAML\Module\oidc\Admin\ConfigOverview\Section[]
     * @throws \Exception
     */
    public function build(array $trustMarks = []): array
    {
        return [
            $this->buildEntitySection(),
            $this->buildEndpointsSection(),
            $this->buildSignatureKeysSection(),
            $this->buildTrustAnchorsSection(),
            $this->buildTrustMarksSection($trustMarks),
            $this->buildTrustChainLimitsSection(),
            $this->buildCacheSection(),
            $this->buildOutboundHttpSection(),
        ];
    }

    /**
     * @throws \Exception
     */
    protected function buildEntitySection(): Section
    {
        $isEnabled = $this->moduleConfig->getFederationEnabled();

        return new Section(
            Translate::noop('Entity'),
            'entity',
            new Row(
                Translate::noop('Federation Enabled'),
                $this->yesNo($isEnabled),
                ConfigOverviewValueTypeEnum::Text,
                ModuleConfig::OPTION_FEDERATION_ENABLED,
                $isEnabled ? null : Translate::noop(
                    'All OpenID Federation capabilities are off, and the federation endpoints are ' .
                    'not served. The settings below are inert until this is enabled.',
                ),
            ),
            $this->buildIssuerRow(
                Translate::noop('Also this entity\'s Entity Identifier in the federation.'),
                Translate::noop(
                    'Not explicitly configured, so it is derived from the current HTTP host. Since ' .
                    'this is also the Entity Identifier, it can change depending on how the OP is ' .
                    'reached, which breaks Trust Chain resolution.',
                ),
            ),
            $this->buildOptionalTextRow(
                Translate::noop('Organization Name'),
                $this->moduleConfig->getOrganizationName(),
                ModuleConfig::OPTION_ORGANIZATION_NAME,
            ),
            $this->buildOptionalTextRow(
                Translate::noop('Display Name'),
                $this->moduleConfig->getDisplayName(),
                ModuleConfig::OPTION_DISPLAY_NAME,
            ),
            $this->buildOptionalTextRow(
                Translate::noop('Description'),
                $this->moduleConfig->getDescription(),
                ModuleConfig::OPTION_DESCRIPTION,
            ),
            new Row(
                Translate::noop('Keywords'),
                $this->moduleConfig->getKeywords() ?? [],
                ConfigOverviewValueTypeEnum::StringList,
                ModuleConfig::OPTION_KEYWORDS,
            ),
            new Row(
                Translate::noop('Contacts'),
                $this->moduleConfig->getContacts() ?? [],
                ConfigOverviewValueTypeEnum::StringList,
                ModuleConfig::OPTION_CONTACTS,
            ),
            $this->buildOptionalUrlRow(
                Translate::noop('Logo URI'),
                $this->moduleConfig->getLogoUri(),
                ModuleConfig::OPTION_LOGO_URI,
            ),
            $this->buildOptionalUrlRow(
                Translate::noop('Policy URI'),
                $this->moduleConfig->getPolicyUri(),
                ModuleConfig::OPTION_POLICY_URI,
            ),
            $this->buildOptionalUrlRow(
                Translate::noop('Information URI'),
                $this->moduleConfig->getInformationUri(),
                ModuleConfig::OPTION_INFORMATION_URI,
            ),
            $this->buildOptionalUrlRow(
                Translate::noop('Organization URI'),
                $this->moduleConfig->getOrganizationUri(),
                ModuleConfig::OPTION_ORGANIZATION_URI,
            ),
            $this->buildDurationRow(
                Translate::noop('Entity Statement Duration'),
                $this->moduleConfig->getFederationEntityStatementDuration(),
                ModuleConfig::OPTION_FEDERATION_ENTITY_STATEMENT_DURATION,
                Translate::noop(
                    'Sets the Expiration Time (exp) claim on Entity Statements published by this OP.',
                ),
            ),
        );
    }

    /**
     * @throws \Exception
     */
    protected function buildEndpointsSection(): Section
    {
        return new Section(
            Translate::noop('Endpoints'),
            'endpoints',
            new Row(
                Translate::noop('Federation Configuration URL'),
                $this->routes->urlFederationConfiguration(),
                ConfigOverviewValueTypeEnum::Url,
                null,
                $this->moduleConfig->getFederationEnabled() ?
                null :
                Translate::noop('Not served, since OpenID Federation is disabled.'),
            ),
        );
    }

    protected function buildSignatureKeysSection(): Section
    {
        $keyPairBag = null;
        $error = null;

        try {
            $keyPairBag = $this->moduleConfig->getFederationSignatureKeyPairBag();
        } catch (Throwable $exception) {
            $error = $this->describeResolutionError(
                $exception,
                ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS,
            );
        }

        return new Section(
            Translate::noop('Signature algorithms and public keys'),
            'signature-keys',
            new Row(
                Translate::noop('Federation Signature Key Pairs'),
                $keyPairBag,
                ConfigOverviewValueTypeEnum::SignatureKeyPairs,
                ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS,
                Translate::noop(
                    'Used to sign Entity Statements. The first entry is the default signing key. ' .
                    'These keys should not be the same as the protocol (Connect) signing keys.',
                ),
                $error,
            ),
        );
    }

    /**
     * @throws \Exception
     */
    protected function buildTrustAnchorsSection(): Section
    {
        // getFederationTrustAnchors() throws when federation is enabled without any Trust Anchor,
        // which is exactly the misconfiguration an administrator would open this screen to find.
        $trustAnchors = [];
        $error = null;

        try {
            $trustAnchors = $this->moduleConfig->getFederationTrustAnchors();
        } catch (Throwable $exception) {
            $error = $this->describeResolutionError($exception, ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS);
        }

        $trustAnchorList = $this->buildTrustAnchorList($trustAnchors);

        // A JWKS which is neither a string nor null makes getTrustAnchorJwksJson() throw at runtime,
        // so it must not be shown as if the JWKS were simply omitted.
        if (is_null($error) && $this->hasInvalidJwks($trustAnchorList)) {
            $error = Translate::noop(
                'At least one Trust Anchor has a JWKS value which is neither a JSON string nor null. ' .
                'Trust Chain validation against it will fail.',
            );
        }

        $authorityHints = $this->moduleConfig->getFederationAuthorityHints() ?? [];

        return new Section(
            Translate::noop('Trust Anchors and Authority Hints'),
            'trust-anchors',
            new Row(
                Translate::noop('Trust Anchors'),
                $trustAnchorList,
                ConfigOverviewValueTypeEnum::TrustAnchors,
                ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS,
                Translate::noop(
                    'A Trust Anchor without a JWKS is validated only by the keys acquired during ' .
                    'Trust Chain resolution, so its security relies on TLS alone.',
                ),
                $error,
            ),
            new Row(
                Translate::noop('Authority Hints'),
                $authorityHints,
                ConfigOverviewValueTypeEnum::StringList,
                ModuleConfig::OPTION_FEDERATION_AUTHORITY_HINTS,
                Translate::noop(
                    'Entity Identifiers of the Intermediates or Trust Anchors directly above this ' .
                    'entity. Required if this entity has a Superior.',
                ),
            ),
        );
    }

    /**
     * @param \SimpleSAML\OpenID\Federation\TrustMark[] $trustMarks
     * @throws \Exception
     */
    protected function buildTrustMarksSection(array $trustMarks): Section
    {
        $trustMarkList = $this->buildTrustMarkList($trustMarks, $unreadableTrustMarkCount);
        $staticTokenCount = count($this->moduleConfig->getFederationTrustMarkTokens() ?? []);
        $dynamicTrustMarks = $this->moduleConfig->getFederationDynamicTrustMarks() ?? [];
        $participationLimits = $this->moduleConfig->getFederationParticipationLimitByTrustMarks();
        // Warnings are fixed sentences rather than interpolated ones, so that they resolve against
        // the message catalog. The offending entries are visible in the row value itself.
        $hasUnknownLimitIds = $this->findUnknownParticipationLimitIds($participationLimits) !== [];
        $hasMalformedLimits = $this->hasMalformedParticipationLimits($participationLimits);

        $participationLimitsWarning = match (true) {
            $hasUnknownLimitIds && $hasMalformedLimits => Translate::noop(
                'Unrecognized limit identifiers and entries of an unexpected shape are configured. ' .
                'The runtime validator rejects both, so federation participation will fail for the ' .
                'affected Trust Anchors.',
            ),
            $hasUnknownLimitIds => Translate::noop(
                'Unrecognized limit identifiers are configured, which the runtime validator rejects. ' .
                'Only \'one_of\' and \'all_of\' are supported.',
            ),
            $hasMalformedLimits => Translate::noop(
                'Some entries have an unexpected shape. Each Trust Anchor must map to a list of ' .
                'limits, and each limit to a list of Trust Mark Type strings.',
            ),
            default => null,
        };

        return new Section(
            Translate::noop('Trust Marks'),
            'trust-marks',
            new Row(
                Translate::noop('Resolved Trust Marks'),
                $trustMarkList,
                ConfigOverviewValueTypeEnum::TrustMarks,
                null,
                Translate::noop(
                    'Statically configured tokens together with the dynamically fetched ones. A ' .
                    'Trust Mark which could not be fetched is reported as a message at the top of ' .
                    'this screen instead of appearing here.',
                ),
                $unreadableTrustMarkCount > 0 ? Translate::noop(
                    'At least one resolved Trust Mark could not be read and is not listed here, for ' .
                    'example because its \'trust_mark_type\' claim is missing. The reason was ' .
                    'written to the SimpleSAMLphp log.',
                ) : null,
            ),
            $this->buildSecretCountRow(
                Translate::noop('Statically Configured Trust Mark Tokens'),
                $staticTokenCount,
                ModuleConfig::OPTION_FEDERATION_TRUST_MARK_TOKENS,
                Translate::noop(
                    'Signed JWTs held in configuration, intended for long lasting or non-expiring ' .
                    'Trust Marks. Their decoded payloads are listed above.',
                ),
            ),
            new Row(
                Translate::noop('Dynamically Fetched Trust Marks'),
                $this->buildDynamicTrustMarkMap($dynamicTrustMarks),
                ConfigOverviewValueTypeEnum::StringMap,
                ModuleConfig::OPTION_FEDERATION_DYNAMIC_TRUST_MARKS,
                Translate::noop('Trust Mark Type, and the Trust Mark Issuer it is fetched from.'),
            ),
            new Row(
                Translate::noop('Trust Mark Status Endpoint Usage Policy'),
                $this->describeTrustMarkStatusPolicy(
                    $this->moduleConfig->getFederationTrustMarkStatusEndpointUsagePolicy(),
                ),
                // UI text built from message IDs, so it stays translatable.
                ConfigOverviewValueTypeEnum::Text,
                ModuleConfig::OPTION_FEDERATION_TRUST_MARK_STATUS_ENDPOINT_USAGE_POLICY,
                Translate::noop(
                    'When the Trust Mark Issuer\'s status endpoint is consulted to check whether a ' .
                    'Trust Mark is still valid.',
                ),
            ),
            new Row(
                Translate::noop('Federation Participation Limits'),
                $this->buildParticipationLimits($participationLimits),
                ConfigOverviewValueTypeEnum::Json,
                ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS,
                Translate::noop(
                    'Per Trust Anchor, the Trust Marks an entity must hold in order to participate. ' .
                    '\'one_of\' requires at least one from the list, \'all_of\' requires them all. ' .
                    'Trust Anchors which are not listed apply no Trust Mark limit.',
                ),
                $participationLimitsWarning,
            ),
        );
    }

    /**
     * @throws \Exception
     */
    protected function buildTrustChainLimitsSection(): Section
    {
        return new Section(
            Translate::noop('Trust Chain resolution limits'),
            'trust-chain-limits',
            new Row(
                Translate::noop('Maximum Trust Chain Depth'),
                (string)$this->moduleConfig->getFederationMaxTrustChainDepth(),
                ConfigOverviewValueTypeEnum::RawText,
                ModuleConfig::OPTION_FEDERATION_MAX_TRUST_CHAIN_DEPTH,
                Translate::noop('Hops from the leaf entity up to a Trust Anchor. Clamped by the library to 1..20.'),
            ),
            new Row(
                Translate::noop('Maximum Authority Hints per Entity'),
                (string)$this->moduleConfig->getFederationMaxAuthorityHints(),
                ConfigOverviewValueTypeEnum::RawText,
                ModuleConfig::OPTION_FEDERATION_MAX_AUTHORITY_HINTS,
                Translate::noop('The branching factor. Clamped by the library to 1..12.'),
            ),
            new Row(
                Translate::noop('Maximum Entity Statement Fetches per Resolution'),
                (string)$this->moduleConfig->getFederationMaxTrustChainFetches(),
                ConfigOverviewValueTypeEnum::RawText,
                ModuleConfig::OPTION_FEDERATION_MAX_TRUST_CHAIN_FETCHES,
                Translate::noop(
                    'Depth and authority hints multiply out, so this budget and the timeout below ' .
                    'are the effective bounds. Clamped by the library to 1..1000.',
                ),
            ),
            new Row(
                Translate::noop('Trust Chain Resolve Timeout (seconds)'),
                (string)$this->moduleConfig->getFederationTrustChainResolveTimeout(),
                ConfigOverviewValueTypeEnum::RawText,
                ModuleConfig::OPTION_FEDERATION_TRUST_CHAIN_RESOLVE_TIMEOUT,
                Translate::noop('Wall-clock deadline for one resolution. Clamped by the library to 1..300.'),
            ),
            new Row(
                Translate::noop('Maximum Fetch Response Size (bytes)'),
                $this->formatBytes($this->moduleConfig->getFederationMaxFetchSizeBytes()),
                ConfigOverviewValueTypeEnum::RawText,
                ModuleConfig::OPTION_FEDERATION_MAX_FETCH_SIZE_BYTES,
                Translate::noop(
                    'These limits matter because Trust Chain resolution is reachable on an ' .
                    'unauthenticated path, walking entity configurations fetched from arbitrary, ' .
                    'possibly hostile, federation entities.',
                ),
            ),
        );
    }

    /**
     * @throws \Exception
     */
    protected function buildCacheSection(): Section
    {
        $adapterClass = $this->moduleConfig->getFederationCacheAdapterClass();
        $adapterArgumentCount = count($this->moduleConfig->getFederationCacheAdapterArguments());
        $isCachingActive = !is_null($adapterClass);

        $notUsedNote = Translate::noop('Not used, since no federation cache adapter is configured.');

        return new Section(
            Translate::noop('Cache'),
            'cache',
            new Row(
                Translate::noop('Cache Adapter'),
                $adapterClass ?? Translate::noop('N/A'),
                $isCachingActive ? ConfigOverviewValueTypeEnum::RawText : ConfigOverviewValueTypeEnum::Text,
                ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER,
                $isCachingActive ? null : Translate::noop(
                    'Not set, so no federation caching is performed and every Trust Chain ' .
                    'resolution refetches. Setting a cache adapter is recommended in production.',
                ),
            ),
            $this->buildSecretCountRow(
                Translate::noop('Cache Adapter Arguments'),
                $adapterArgumentCount,
                ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER_ARGUMENTS,
                Translate::noop(
                    'Values are not shown, since adapter arguments can carry connection credentials.',
                ),
            ),
            $this->buildDurationRow(
                Translate::noop('Maximum Cache Duration for Fetched Artifacts'),
                $this->moduleConfig->getFederationCacheMaxDurationForFetched(),
                ModuleConfig::OPTION_FEDERATION_CACHE_MAX_DURATION_FOR_FETCHED,
                $isCachingActive ? Translate::noop(
                    'Caps how long a fetched artifact is cached, since its own expiry is set by the ' .
                    'issuer and can be long. Lower values propagate federation changes faster.',
                ) : $notUsedNote,
            ),
            $this->buildDurationRow(
                Translate::noop('Cache Duration for Produced Artifacts'),
                $this->moduleConfig->getFederationEntityStatementCacheDurationForProduced(),
                ModuleConfig::OPTION_FEDERATION_CACHE_DURATION_FOR_PRODUCED,
                $isCachingActive ? Translate::noop(
                    'Avoids recomputing the JWS signature for statements this OP publishes on every ' .
                    'request.',
                ) : $notUsedNote,
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
            $this->buildHttpClientOptionsRow(
                Translate::noop('Federation HTTP Client Options'),
                $this->moduleConfig->getFederationHttpClientOptions(),
                ModuleConfig::OPTION_FEDERATION_HTTP_CLIENT_OPTIONS,
                Translate::noop(
                    'Merged over the library\'s hardening defaults, so a value set here replaces the ' .
                    'corresponding default. Of note: \'timeout\' and \'connect_timeout\' (Guzzle ' .
                    'reads 0 as no timeout), and \'allow_redirects\' (the library restricts ' .
                    'redirects to at most 3 https hops).',
                ),
                Translate::noop(
                    'Not set, so the library\'s hardening defaults apply, including TLS ' .
                    'verification and restricted redirects.',
                ),
            ),
        );
    }

    /**
     * @param array $trustAnchors Trust Anchor ID to JWKS JSON string, or null.
     * @return array<array{id: string, jwks: ?string, isJwksInvalid: bool}>
     */
    protected function buildTrustAnchorList(array $trustAnchors): array
    {
        $list = [];

        /** @var mixed $jwks */
        foreach ($trustAnchors as $trustAnchorId => $jwks) {
            // Mirrors ModuleConfig::getTrustAnchorJwksJson(): any string is accepted, null means the
            // JWKS was intentionally not provided, and anything else is a configuration error.
            $list[] = [
                'id' => (string)$trustAnchorId,
                'jwks' => is_string($jwks) ? $jwks : null,
                'isJwksInvalid' => !is_string($jwks) && !is_null($jwks),
            ];
        }

        return $list;
    }

    /**
     * @param array<array{id: string, jwks: ?string, isJwksInvalid: bool}> $trustAnchorList
     */
    protected function hasInvalidJwks(array $trustAnchorList): bool
    {
        foreach ($trustAnchorList as $trustAnchor) {
            if ($trustAnchor['isJwksInvalid']) {
                return true;
            }
        }

        return false;
    }

    /**
     * Read the resolved Trust Marks for display.
     *
     * A Trust Mark can be a well-formed JWT and still fail here, for example when its
     * 'trust_mark_type' claim is missing, since the factory only rejects some malformed input. Such
     * a Trust Mark must not take the whole screen down, but it must not vanish silently either, so
     * the count of unreadable ones is reported back to the caller.
     *
     * @param \SimpleSAML\OpenID\Federation\TrustMark[] $trustMarks
     * @param-out int $unreadableCount
     * @return array<array{type: string, payload: array}>
     */
    protected function buildTrustMarkList(array $trustMarks, ?int &$unreadableCount = null): array
    {
        $list = [];
        $unreadableCount = 0;

        foreach ($trustMarks as $trustMark) {
            if (!$trustMark instanceof TrustMark) {
                $unreadableCount++;
                continue;
            }

            try {
                $list[] = [
                    'type' => $trustMark->getTrustMarkType(),
                    'payload' => $trustMark->getPayload(),
                ];
            } catch (Throwable $exception) {
                $unreadableCount++;
                $this->logger->error(
                    'Configuration overview could not read a resolved Trust Mark: ' . $exception->getMessage(),
                    ['exceptionClass' => $exception::class],
                );
            }
        }

        return $list;
    }

    /**
     * Present the dynamic Trust Mark configuration as a map of Trust Mark Type to a single-item
     * list holding its issuer, matching the StringMap rendering used elsewhere.
     *
     * @return array<string, string[]>
     */
    protected function buildDynamicTrustMarkMap(array $dynamicTrustMarks): array
    {
        $map = [];

        /** @var mixed $trustMarkIssuerId */
        foreach ($dynamicTrustMarks as $trustMarkType => $trustMarkIssuerId) {
            $map[(string)$trustMarkType] = [(string)$trustMarkIssuerId];
        }

        return $map;
    }

    /**
     * Normalize the participation limits into plain, displayable arrays.
     *
     * Every configured limit identifier is kept, including ones LimitsEnum does not know, because
     * FederationParticipationValidator calls LimitsEnum::from() on the raw map and rejects those at
     * runtime. Dropping them here would make this screen report "no limit" for a Trust Anchor whose
     * configuration actually fails.
     */
    protected function buildParticipationLimits(array $participationLimits): array
    {
        $limits = [];

        /** @var mixed $limitsForAnchor */
        foreach ($participationLimits as $trustAnchorId => $limitsForAnchor) {
            if (!is_array($limitsForAnchor)) {
                // Kept as configured so the malformed shape stays visible; the row warning explains it.
                /** @psalm-suppress MixedAssignment */
                $limits[(string)$trustAnchorId] = $limitsForAnchor;
                continue;
            }

            $normalized = [];

            /** @var mixed $trustMarkTypes */
            foreach ($limitsForAnchor as $limitId => $trustMarkTypes) {
                /** @psalm-suppress MixedAssignment */
                $normalized[(string)$limitId] = is_array($trustMarkTypes) ?
                array_values($trustMarkTypes) :
                $trustMarkTypes;
            }

            $limits[(string)$trustAnchorId] = $normalized;
        }

        return $limits;
    }

    /**
     * Whether any participation limit entry has a shape the runtime validator rejects: a Trust
     * Anchor which does not map to a list of limits, a limit which does not map to a list, or a
     * Trust Mark Type which is not a string.
     */
    protected function hasMalformedParticipationLimits(array $participationLimits): bool
    {
        /** @var mixed $limitsForAnchor */
        foreach ($participationLimits as $limitsForAnchor) {
            if (!is_array($limitsForAnchor)) {
                return true;
            }

            /** @var mixed $trustMarkTypes */
            foreach ($limitsForAnchor as $trustMarkTypes) {
                if (!is_array($trustMarkTypes)) {
                    return true;
                }

                /** @var mixed $trustMarkType */
                foreach ($trustMarkTypes as $trustMarkType) {
                    if (!is_string($trustMarkType)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Limit identifiers which are configured but which LimitsEnum does not recognize.
     *
     * @return string[]
     */
    protected function findUnknownParticipationLimitIds(array $participationLimits): array
    {
        $unknown = [];

        /** @var mixed $limitsForAnchor */
        foreach ($participationLimits as $limitsForAnchor) {
            if (!is_array($limitsForAnchor)) {
                continue;
            }

            foreach (array_keys($limitsForAnchor) as $limitId) {
                $limitId = (string)$limitId;

                if (is_null(LimitsEnum::tryFrom($limitId)) && !in_array($limitId, $unknown, true)) {
                    $unknown[] = $limitId;
                }
            }
        }

        return $unknown;
    }

    /**
     * Human readable description of when the Trust Mark status endpoint is consulted.
     *
     * Note that TrustMarkStatusEndpointUsagePolicyEnum is a pure enum, so it has no backing value.
     */
    protected function describeTrustMarkStatusPolicy(TrustMarkStatusEndpointUsagePolicyEnum $policy): string
    {
        return match ($policy) {
            TrustMarkStatusEndpointUsagePolicyEnum::Required =>
            Translate::noop('Always required'),
            TrustMarkStatusEndpointUsagePolicyEnum::RequiredForNonExpiringTrustMarksOnly =>
            Translate::noop('Required for non-expiring Trust Marks only'),
            TrustMarkStatusEndpointUsagePolicyEnum::RequiredIfEndpointProvided =>
            Translate::noop('Required if the issuer provides the endpoint'),
            TrustMarkStatusEndpointUsagePolicyEnum::RequiredIfEndpointProvidedForNonExpiringTrustMarksOnly =>
            Translate::noop('Required if the issuer provides the endpoint, for non-expiring Trust Marks only'),
            TrustMarkStatusEndpointUsagePolicyEnum::NotUsed =>
            Translate::noop('Not used'),
        };
    }
}

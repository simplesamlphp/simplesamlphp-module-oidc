<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\ProtocolOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\Row;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\Section;
use SimpleSAML\Module\oidc\Codebooks\ConfigOverviewValueTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\DcrRegistrationAuthEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;

#[CoversClass(ProtocolOverviewBuilder::class)]
#[CoversClass(Row::class)]
#[CoversClass(Section::class)]
class ProtocolOverviewBuilderTest extends TestCase
{
    use OverviewTestTrait;
    use ProtocolOverviewTestTrait;

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(ProtocolOverviewBuilder::class, $this->buildProtocolOverviewBuilder());
    }

    public function testCanBuildSections(): void
    {
        $sections = $this->buildProtocolOverviewBuilder()->build();

        $this->assertNotEmpty($sections);

        foreach ($sections as $section) {
            $this->assertInstanceOf(Section::class, $section);
            $this->assertNotEmpty($section->getTitle());
            $this->assertNotEmpty($section->getAnchor());
            $this->assertNotEmpty($section->getRows());
        }
    }

    public function testSectionAnchorsAreUnique(): void
    {
        $anchors = array_map(
            fn(Section $section): string => $section->getAnchor(),
            $this->buildProtocolOverviewBuilder()->build(),
        );

        $this->assertSame($anchors, array_unique($anchors));
    }

    public function testEveryRowHasALabel(): void
    {
        foreach ($this->flattenRows($this->buildProtocolOverviewBuilder()->build()) as $row) {
            $this->assertNotEmpty($row->getLabel());
        }
    }

    public function testEachConfigOptionIsShownOnlyOnce(): void
    {
        $configOptions = [];

        foreach ($this->flattenRows($this->buildProtocolOverviewBuilder()->build()) as $row) {
            if (is_null($configOption = $row->getConfigOption())) {
                continue;
            }

            $configOptions[] = $configOption;
        }

        $this->assertSame($configOptions, array_unique($configOptions));
    }

    public function testRendersDurationsIncludingYears(): void
    {
        $sections = $this->buildProtocolOverviewBuilder(
            [ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL => 'P1Y'],
        )->build();

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL);

        $this->assertNotNull($row);
        $this->assertSame('1 year (P1Y)', $row->getValue());
    }

    public function testNotesWhenIssuerIsNotExplicitlyConfigured(): void
    {
        $configuredRow = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder()->build(),
            ModuleConfig::OPTION_ISSUER,
        );
        $this->assertNotNull($configuredRow);
        $this->assertNull($configuredRow->getNote());

        $derivedRow = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([ModuleConfig::OPTION_ISSUER => null])->build(),
            ModuleConfig::OPTION_ISSUER,
        );
        $this->assertNotNull($derivedRow);
        $this->assertStringContainsString('derived', (string)$derivedRow->getNote());
    }

    /**
     * A broken option must be reported in place rather than take the screen down, since this is the
     * screen an administrator opens to diagnose it. Mirrors the federation screen's behaviour.
     */
    public function testReportsSignatureKeyPairErrorInPlace(): void
    {
        $sections = $this->buildProtocolOverviewBuilder([
            ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS => [],
        ])->build();

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS);

        $this->assertNotNull($row);
        $this->assertNull($row->getValue());
        $this->assertStringContainsString('written to the SimpleSAMLphp log', (string)$row->getWarning());
    }

    public function testReportsIssuerErrorInPlace(): void
    {
        // With no configured issuer and a host which resolves to an empty string, getIssuer() throws.
        $sections = $this->buildProtocolOverviewBuilder(
            [ModuleConfig::OPTION_ISSUER => null],
            derivedHost: '',
        )->build();

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_ISSUER);

        $this->assertNotNull($row);
        $this->assertSame('N/A', $row->getValue());
        $this->assertNotNull($row->getWarning());
    }

    /**
     * The destination policy options are what an administrator comes to this screen to check when
     * outbound fetches start failing, so a malformed one has to fail on its own row. Resolving them
     * ahead of the rows would throw before any row existed and take the whole screen down.
     */
    public function testReportsAMalformedDestinationPolicyOptionInPlace(): void
    {
        $sections = $this->buildProtocolOverviewBuilder([
            // A string where a list belongs, which is how this is most easily mistyped.
            ModuleConfig::OPTION_OUTBOUND_ALLOWED_HOSTS => 'rp.internal.example',
        ])->build();

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_OUTBOUND_ALLOWED_HOSTS);

        $this->assertNotNull($row);
        $this->assertSame('N/A', $row->getValue());
        $this->assertNotNull($row->getWarning());

        // The rest of the screen still built, which is the point of failing in place.
        $this->assertNotNull(
            $this->findRowForOption($sections, ModuleConfig::OPTION_OUTBOUND_ADDRESS_PINNING_MODE),
        );
    }

    /**
     * Who may introspect another client's tokens is exactly the sort of thing an administrator opens
     * this screen to check, so a mistyped list has to fail on its own row rather than take the screen
     * down with it.
     */
    public function testReportsMalformedIntrospectionResourceServersInPlace(): void
    {
        $sections = $this->buildProtocolOverviewBuilder([
            ModuleConfig::OPTION_API_ENABLED => true,
            ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED => true,
            // A single client written as a string rather than as a list of one.
            ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RESOURCE_SERVER_CLIENT_IDS =>
                'resource-server',
        ])->build();

        $row = $this->findRowForOption(
            $sections,
            ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RESOURCE_SERVER_CLIENT_IDS,
        );

        $this->assertNotNull($row);
        $this->assertSame('N/A', $row->getValue());
        $this->assertNotNull($row->getWarning());

        // The rest of the API section still built.
        $this->assertNotNull($this->findRowForOption($sections, ModuleConfig::OPTION_API_TOKENS));
    }

    /**
     * A non-string issuer makes getOptionalString() throw, which both getIssuer() and
     * isIssuerConfigured() go through. Resolving the configured state outside the guard would
     * rethrow and take the screen down anyway.
     */
    public function testSurvivesNonStringIssuerValue(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([ModuleConfig::OPTION_ISSUER => ['not-a-string']])->build(),
            ModuleConfig::OPTION_ISSUER,
        );

        $this->assertNotNull($row);
        $this->assertSame('N/A', $row->getValue());
        $this->assertNotNull($row->getWarning());
        // Neither note applies: the issuer is configured, it is simply unusable.
        $this->assertNull($row->getNote());
    }

    /**
     * The scope list pulls in Verifiable Credential scopes, so a malformed VCI configuration can
     * break protocol rows. When that happens the descriptive notes must be suppressed, otherwise the
     * row claims things about a value it could not resolve.
     */
    public function testSuppressesNotesWhenScopeResolutionFails(): void
    {
        $sections = $this->buildProtocolOverviewBuilder([
            ModuleConfig::OPTION_VCI_ENABLED => true,
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => 'not-an-array',
        ])->build();

        $scopesRow = $this->findRowForOption($sections, ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES);
        $this->assertNotNull($scopesRow);
        $this->assertSame([], $scopesRow->getValue());
        $this->assertNotNull($scopesRow->getWarning());
        $this->assertNull($scopesRow->getNote());

        $defaultScopesRow = $this->findRowForOption($sections, ModuleConfig::OPTION_DCR_DEFAULT_SCOPES);
        $this->assertNotNull($defaultScopesRow);
        $this->assertSame([], $defaultScopesRow->getValue());
        $this->assertNotNull($defaultScopesRow->getWarning());
        // Must not simultaneously claim the fallback contains every supported scope.
        $this->assertNull($defaultScopesRow->getNote());
    }

    public function testDoesNotExposeConfigurationErrorDetail(): void
    {
        $loggerMock = $this->createMock(LoggerService::class);
        $loggerMock->expects($this->atLeastOnce())
            ->method('error')
            ->with($this->stringContains(ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS));

        $builder = new ProtocolOverviewBuilder(
            $this->buildOverviewModuleConfig([ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS => []]),
            $this->createMock(Routes::class),
            new DateIntervalFormatter(),
            $loggerMock,
            $this->createMock(ClaimTranslatorExtractor::class),
        );

        $row = $this->findRowForOption(
            $builder->build(),
            ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS,
        );

        $this->assertNotNull($row);
        $this->assertStringNotContainsString('At least one', (string)$row->getWarning());
    }

    public function testNeverExposesEncryptionKey(): void
    {
        $sections = $this->buildProtocolOverviewBuilder(
            [ModuleConfig::OPTION_ENCRYPTION_KEY => 'super-secret-encryption-key'],
        )->build();

        $this->assertStringNotContainsString(
            'super-secret-encryption-key',
            $this->renderableContent($sections),
        );

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_ENCRYPTION_KEY);
        $this->assertNotNull($row);
        $this->assertStringContainsString('Dedicated', (string)$row->getValue());
    }

    public function testReportsEncryptionKeyFallbackToSecretSalt(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder()->build(),
            ModuleConfig::OPTION_ENCRYPTION_KEY,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('secret salt', (string)$row->getValue());
    }

    public function testNeverExposesInitialAccessTokens(): void
    {
        $sections = $this->buildProtocolOverviewBuilder([
            ModuleConfig::OPTION_DCR_ENABLED => true,
            ModuleConfig::OPTION_DCR_INITIAL_ACCESS_TOKENS => ['super-secret-initial-access-token'],
        ])->build();

        $this->assertStringNotContainsString(
            'super-secret-initial-access-token',
            $this->renderableContent($sections),
        );

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_DCR_INITIAL_ACCESS_TOKENS);
        $this->assertNotNull($row);
        $this->assertSame('1', $row->getValue());
    }

    public function testNeverExposesApiTokens(): void
    {
        $sections = $this->buildProtocolOverviewBuilder([
            ModuleConfig::OPTION_API_ENABLED => true,
            ModuleConfig::OPTION_API_TOKENS => ['super-secret-api-token' => ['scope']],
        ])->build();

        $this->assertStringNotContainsString(
            'super-secret-api-token',
            $this->renderableContent($sections),
        );
    }

    public function testNeverExposesCacheAdapterArguments(): void
    {
        $sections = $this->buildProtocolOverviewBuilder([
            ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER_ARGUMENTS => [
                'memcached://user:super-secret-password@localhost',
            ],
        ])->build();

        $this->assertStringNotContainsString(
            'super-secret-password',
            $this->renderableContent($sections),
        );
    }

    public function testRedactsCredentialsInHttpClientOptions(): void
    {
        $sections = $this->buildProtocolOverviewBuilder([
            ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS => [
                'timeout' => 9,
                'auth' => ['api-user', 'super-secret-basic-password'],
                'proxy' => 'http://proxy-user:super-secret-proxy-password@proxy.example.org:8080',
                'headers' => ['Authorization' => 'Bearer super-secret-bearer-token'],
                'cert' => ['/path/to/client.pem', 'super-secret-cert-passphrase'],
            ],
        ])->build();

        $content = $this->renderableContent($sections);

        $this->assertStringNotContainsString('super-secret-basic-password', $content);
        $this->assertStringNotContainsString('super-secret-proxy-password', $content);
        $this->assertStringNotContainsString('super-secret-bearer-token', $content);
        $this->assertStringNotContainsString('super-secret-cert-passphrase', $content);

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS);
        $this->assertNotNull($row);

        $value = $row->getValue();
        $this->assertIsArray($value);

        // Allowlisted options stay visible, everything else keeps only its name.
        $this->assertSame(9, $value['timeout']);
        $this->assertSame('(not shown)', $value['auth']);
        $this->assertSame('(not shown)', $value['proxy']);
        $this->assertSame('(not shown)', $value['headers']);
        $this->assertSame('(not shown)', $value['cert']);
    }

    public function testStillDetectsDisabledTlsVerificationBehindRedaction(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([
                ModuleConfig::OPTION_BACKCHANNEL_LOGOUT_HTTP_CLIENT_OPTIONS => [
                    'verify' => false,
                    'auth' => ['user', 'super-secret-password'],
                ],
            ])->build(),
            ModuleConfig::OPTION_BACKCHANNEL_LOGOUT_HTTP_CLIENT_OPTIONS,
        );

        $this->assertNotNull($row);
        $this->assertNotNull($row->getWarning());

        $value = $row->getValue();
        $this->assertIsArray($value);
        $this->assertFalse($value['verify']);
        $this->assertSame('(not shown)', $value['auth']);
    }

    public function testConfiguredValuesAreNotTranslatable(): void
    {
        $sections = $this->buildProtocolOverviewBuilder()->build();

        foreach (
            [
                ModuleConfig::OPTION_ISSUER,
                ModuleConfig::OPTION_AUTH_SOURCE,
                ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER,
                ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_TTL,
                ModuleConfig::OPTION_REQUEST_URI_FETCH_TIMEOUT,
                ModuleConfig::OPTION_REQUEST_URI_MAX_SIZE_BYTES,
            ] as $configOption
        ) {
            $row = $this->findRowForOption($sections, $configOption);

            $this->assertNotNull($row, "No row found for $configOption");
            $this->assertSame(
                ConfigOverviewValueTypeEnum::RawText,
                $row->getValueType(),
                "Configured value for $configOption must not be passed through the translator.",
            );
        }
    }

    public function testWarnsWhenTlsVerificationIsDisabled(): void
    {
        $sections = $this->buildProtocolOverviewBuilder([
            ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS => ['verify' => false],
        ])->build();

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS);

        $this->assertNotNull($row);
        $this->assertStringContainsString('man-in-the-middle', (string)$row->getWarning());
    }

    public function testDoesNotWarnAboutTlsVerificationByDefault(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder()->build(),
            ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS,
        );

        $this->assertNotNull($row);
        $this->assertNull($row->getWarning());
    }

    public function testShowsFederationRequestUriAllowlist(): void
    {
        $deniedRow = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder()->build(),
            ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES,
        );
        $this->assertNotNull($deniedRow);
        $this->assertStringContainsString('None', (string)$deniedRow->getValue());
        $this->assertNull($deniedRow->getWarning());

        $allowlistedRow = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES => ['https://rp.example.org/'],
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES,
        );
        $this->assertNotNull($allowlistedRow);
        $this->assertSame(['https://rp.example.org/'], $allowlistedRow->getValue());
        $this->assertNull($allowlistedRow->getWarning());
    }

    public function testWarnsWhenAnyFederationRequestUriIsAllowed(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_ENABLED => true,
                ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES => null,
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('server-side request forgery', (string)$row->getWarning());
    }

    public function testDoesNotWarnAboutRequestUriAllowlistWhenFetchingIsDisabled(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_ENABLED => true,
                ModuleConfig::OPTION_REQUEST_URI_PARAMETER_SUPPORTED => false,
                ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES => null,
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES,
        );

        $this->assertNotNull($row);
        $this->assertNull($row->getWarning());
    }

    /**
     * RequestParamsResolver only takes the federation by-reference path when federation is enabled,
     * so warning about it while federation is off would be a false alarm.
     */
    public function testDoesNotWarnAboutRequestUriAllowlistWhenFederationIsDisabled(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_ENABLED => false,
                ModuleConfig::OPTION_REQUEST_URI_PARAMETER_SUPPORTED => true,
                ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES => null,
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES,
        );

        $this->assertNotNull($row);
        $this->assertNull($row->getWarning());
        $this->assertStringContainsString('Federation is disabled', (string)$row->getNote());
    }

    public function testWarnsWhenDynamicClientRegistrationIsOpen(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([ModuleConfig::OPTION_DCR_ENABLED => true])->build(),
            ModuleConfig::OPTION_DCR_REGISTRATION_AUTH,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('open', (string)$row->getWarning());
    }

    public function testDoesNotWarnAboutOpenRegistrationWhenDcrIsDisabled(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder()->build(),
            ModuleConfig::OPTION_DCR_REGISTRATION_AUTH,
        );

        $this->assertNotNull($row);
        $this->assertNull($row->getWarning());
    }

    public function testWarnsWhenInitialAccessTokenModeHasNoTokens(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([
                ModuleConfig::OPTION_DCR_ENABLED => true,
                ModuleConfig::OPTION_DCR_REGISTRATION_AUTH => DcrRegistrationAuthEnum::InitialAccessToken->value,
                ModuleConfig::OPTION_DCR_INITIAL_ACCESS_TOKENS => [],
            ])->build(),
            ModuleConfig::OPTION_DCR_INITIAL_ACCESS_TOKENS,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('rejected', (string)$row->getWarning());
    }

    public function testWarnsWhenImpersonationProtectionIsDisabled(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([
                ModuleConfig::OPTION_DCR_ENABLED => true,
                ModuleConfig::OPTION_DCR_IMPERSONATION_PROTECTION_ENABLED => false,
            ])->build(),
            ModuleConfig::OPTION_DCR_IMPERSONATION_PROTECTION_ENABLED,
        );

        $this->assertNotNull($row);
        $this->assertNotNull($row->getWarning());
    }

    public function testNotesWhenDcrDefaultScopesFallBackToAllSupported(): void
    {
        $fallbackRow = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder()->build(),
            ModuleConfig::OPTION_DCR_DEFAULT_SCOPES,
        );
        $this->assertNotNull($fallbackRow);
        $this->assertStringContainsString('offline_access', (string)$fallbackRow->getNote());

        $configuredRow = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder(
                [ModuleConfig::OPTION_DCR_DEFAULT_SCOPES => ['openid']],
            )->build(),
            ModuleConfig::OPTION_DCR_DEFAULT_SCOPES,
        );
        $this->assertNotNull($configuredRow);
        $this->assertNull($configuredRow->getNote());
        $this->assertSame(['openid'], $configuredRow->getValue());
    }

    public function testMarksScopeOrigin(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([
                ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES => [
                    'private' => [
                        'description' => 'private scope',
                        'claim_name_prefix' => 'prefix_',
                        'are_multiple_claim_values_allowed' => true,
                        'claims' => ['national_document_id'],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES,
        );

        $this->assertNotNull($row);
        $this->assertSame(ConfigOverviewValueTypeEnum::Scopes, $row->getValueType());

        $scopes = $row->getValue();
        $this->assertIsArray($scopes);

        $scopesByName = array_column($scopes, null, 'name');

        $this->assertSame('Standard', $scopesByName['openid']['origin']);
        $this->assertSame('Custom', $scopesByName['private']['origin']);
        $this->assertSame('prefix_', $scopesByName['private']['claimNamePrefix']);
        $this->assertTrue($scopesByName['private']['areMultipleClaimValuesAllowed']);
        $this->assertSame(['national_document_id'], $scopesByName['private']['claims']);
    }

    public function testRendersAuthProcFiltersInBothConfigForms(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([
                ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS => [
                    10 => ['class' => 'core:AttributeMap'],
                    20 => 'core:TargetedID',
                    30 => ['no-class-key' => 'value'],
                ],
            ])->build(),
            ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS,
        );

        $this->assertNotNull($row);
        $this->assertSame(
            [
                '10: core:AttributeMap',
                '20: core:TargetedID',
                '30: [filter class not set]',
            ],
            $row->getValue(),
        );
    }

    /**
     * SimpleSAMLphp's ProcessingChain runs filters by priority, not by order of declaration, so the
     * overview must show the effective execution order.
     */
    public function testSortsAuthProcFiltersByPriority(): void
    {
        $row = $this->findRowForOption(
            $this->buildProtocolOverviewBuilder([
                ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS => [
                    50 => ['class' => 'core:LastToRun'],
                    10 => ['class' => 'core:FirstToRun'],
                    30 => ['class' => 'core:SecondToRun'],
                ],
            ])->build(),
            ModuleConfig::OPTION_AUTH_PROCESSING_FILTERS,
        );

        $this->assertNotNull($row);
        $this->assertSame(
            [
                '10: core:FirstToRun',
                '30: core:SecondToRun',
                '50: core:LastToRun',
            ],
            $row->getValue(),
        );
    }

    public function testShowsRegistrationEndpointOnlyWhenDcrIsEnabled(): void
    {
        $labels = fn(array $sections): array => array_map(
            fn(Row $row): string => $row->getLabel(),
            $this->flattenRows($sections),
        );

        $this->assertNotContains(
            'Client Registration',
            $labels($this->buildProtocolOverviewBuilder()->build()),
        );

        $this->assertContains(
            'Client Registration',
            $labels($this->buildProtocolOverviewBuilder([ModuleConfig::OPTION_DCR_ENABLED => true])->build()),
        );
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\AbstractOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\FederationOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\Section;
use SimpleSAML\Module\oidc\Codebooks\ConfigOverviewValueTypeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\TrustMarkStatusEndpointUsagePolicyEnum;
use SimpleSAML\OpenID\Federation\TrustMark;

#[CoversClass(FederationOverviewBuilder::class)]
#[CoversClass(AbstractOverviewBuilder::class)]
#[AllowMockObjectsWithoutExpectations]
class FederationOverviewBuilderTest extends TestCase
{
    use OverviewTestTrait;
    use FederationOverviewTestTrait;


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(FederationOverviewBuilder::class, $this->buildFederationOverviewBuilder());
    }


    public function testCanBuildSections(): void
    {
        $sections = $this->buildFederationOverviewBuilder()->build();

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
            $this->buildFederationOverviewBuilder()->build(),
        );

        $this->assertSame($anchors, array_unique($anchors));
    }


    public function testEveryRowHasALabel(): void
    {
        foreach ($this->flattenRows($this->buildFederationOverviewBuilder()->build()) as $row) {
            $this->assertNotEmpty($row->getLabel());
        }
    }


    public function testNotesWhenFederationIsDisabled(): void
    {
        $disabledRow = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([ModuleConfig::OPTION_FEDERATION_ENABLED => false])->build(),
            ModuleConfig::OPTION_FEDERATION_ENABLED,
        );
        $this->assertNotNull($disabledRow);
        $this->assertSame('No', $disabledRow->getValue());
        $this->assertStringContainsString('inert', (string)$disabledRow->getNote());

        $enabledRow = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([ModuleConfig::OPTION_FEDERATION_ENABLED => true])->build(),
            ModuleConfig::OPTION_FEDERATION_ENABLED,
        );
        $this->assertNotNull($enabledRow);
        $this->assertSame('Yes', $enabledRow->getValue());
        $this->assertNull($enabledRow->getNote());
    }


    /**
     * Same guard as on the protocol screen: isIssuerConfigured() reads the option through
     * getOptionalString(), which throws for a non-string value.
     */
    public function testSurvivesNonStringIssuerValue(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([ModuleConfig::OPTION_ISSUER => ['not-a-string']])->build(),
            ModuleConfig::OPTION_ISSUER,
        );

        $this->assertNotNull($row);
        $this->assertSame('N/A', $row->getValue());
        $this->assertNotNull($row->getWarning());
        $this->assertNull($row->getNote());
    }


    public function testShowsTrustAnchorsWithAndWithoutJwks(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS => [
                    'https://ta.example.org/' => '{"keys":[]}',
                    'https://ta2.example.org/' => null,
                ],
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS,
        );

        $this->assertNotNull($row);
        $this->assertSame(ConfigOverviewValueTypeEnum::TrustAnchors, $row->getValueType());
        $this->assertSame(
            [
                ['id' => 'https://ta.example.org/', 'jwks' => '{"keys":[]}', 'isJwksInvalid' => false],
                ['id' => 'https://ta2.example.org/', 'jwks' => null, 'isJwksInvalid' => false],
            ],
            $row->getValue(),
        );
        $this->assertNull($row->getWarning());
    }


    /**
     * A JWKS which is neither a string nor null makes ModuleConfig::getTrustAnchorJwksJson() throw
     * at runtime, so it must not be shown as though the JWKS were simply omitted.
     */
    public function testFlagsInvalidTrustAnchorJwks(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS => [
                    'https://ta.example.org/' => ['keys' => []],
                ],
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS,
        );

        $this->assertNotNull($row);
        $this->assertSame(
            [['id' => 'https://ta.example.org/', 'jwks' => null, 'isJwksInvalid' => true]],
            $row->getValue(),
        );
        $this->assertStringContainsString('neither a JSON string nor null', (string)$row->getWarning());
    }


    /**
     * getFederationTrustAnchors() throws when federation is enabled without any Trust Anchor. That
     * is exactly the misconfiguration an administrator opens this screen to diagnose, so it must be
     * reported in place rather than take the page down.
     */
    public function testReportsTrustAnchorConfigurationErrorInPlace(): void
    {
        $sections = $this->buildFederationOverviewBuilder([
            ModuleConfig::OPTION_FEDERATION_ENABLED => true,
            ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS => [],
        ])->build();

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS);

        $this->assertNotNull($row);
        $this->assertNotNull($row->getWarning());
        $this->assertSame([], $row->getValue());
        // The raw exception text can quote configured values back, so it goes to the log only.
        $this->assertStringContainsString('written to the SimpleSAMLphp log', (string)$row->getWarning());
    }


    /**
     * The exception message from a broken option must never reach the screen, since config
     * validation and the openid key loading path both quote configured values in their messages.
     */
    public function testLogsRatherThanRendersConfigurationErrorDetail(): void
    {
        $loggerMock = $this->createMock(LoggerService::class);
        $loggerMock->expects($this->atLeastOnce())
            ->method('error')
            ->with($this->stringContains(ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS));

        $builder = new FederationOverviewBuilder(
            $this->buildOverviewModuleConfig([
                ModuleConfig::OPTION_FEDERATION_ENABLED => true,
                ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS => [],
            ]),
            $this->createMock(Routes::class),
            new DateIntervalFormatter(),
            $loggerMock,
        );

        $row = $this->findRowForOption($builder->build(), ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS);

        $this->assertNotNull($row);
        $this->assertStringNotContainsString('No Trust Anchors have been configured', (string)$row->getWarning());
    }


    public function testShowsAuthorityHints(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_AUTHORITY_HINTS => ['https://intermediate.example.org/'],
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_AUTHORITY_HINTS,
        );

        $this->assertNotNull($row);
        $this->assertSame(['https://intermediate.example.org/'], $row->getValue());
    }


    public function testNeverExposesTrustMarkTokens(): void
    {
        $sections = $this->buildFederationOverviewBuilder([
            ModuleConfig::OPTION_FEDERATION_TRUST_MARK_TOKENS => ['ey-super-secret-trust-mark-token'],
        ])->build();

        $this->assertStringNotContainsString(
            'ey-super-secret-trust-mark-token',
            $this->renderableContent($sections),
        );

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_FEDERATION_TRUST_MARK_TOKENS);
        $this->assertNotNull($row);
        $this->assertSame('1', $row->getValue());
    }


    public function testShowsResolvedTrustMarks(): void
    {
        $trustMark = $this->createMock(TrustMark::class);
        $trustMark->method('getTrustMarkType')->willReturn('https://ta.example.org/trust-mark-type');
        $trustMark->method('getPayload')->willReturn(['trust_mark_type' => 'https://ta.example.org/trust-mark-type']);

        $row = $this->findRowByLabel(
            $this->buildFederationOverviewBuilder()->build([$trustMark]),
            'Resolved Trust Marks',
        );

        $this->assertNotNull($row);
        $this->assertSame(ConfigOverviewValueTypeEnum::TrustMarks, $row->getValueType());
        $this->assertSame(
            [
                [
                    'type' => 'https://ta.example.org/trust-mark-type',
                    'payload' => ['trust_mark_type' => 'https://ta.example.org/trust-mark-type'],
                ],
            ],
            $row->getValue(),
        );
    }


    /**
     * A Trust Mark which cannot be read must not take the screen down, but it must not vanish
     * without a trace either.
     */
    public function testWarnsAboutTrustMarksWhichCanNotBeRead(): void
    {
        $brokenTrustMark = $this->createMock(TrustMark::class);
        $brokenTrustMark->method('getTrustMarkType')->willThrowException(new RuntimeException('broken'));

        $loggerMock = $this->createMock(LoggerService::class);
        $loggerMock->expects($this->once())
            ->method('error')
            ->with($this->stringContains('could not read a resolved Trust Mark'));

        $builder = new FederationOverviewBuilder(
            $this->buildOverviewModuleConfig(),
            $this->createMock(Routes::class),
            new DateIntervalFormatter(),
            $loggerMock,
        );

        $row = $this->findRowByLabel($builder->build([$brokenTrustMark]), 'Resolved Trust Marks');

        $this->assertNotNull($row);
        $this->assertSame([], $row->getValue());
        $this->assertStringContainsString('could not be read', (string)$row->getWarning());
    }


    public function testDoesNotWarnWhenAllTrustMarksAreReadable(): void
    {
        $trustMark = $this->createMock(TrustMark::class);
        $trustMark->method('getTrustMarkType')->willReturn('type');
        $trustMark->method('getPayload')->willReturn([]);

        $row = $this->findRowByLabel(
            $this->buildFederationOverviewBuilder()->build([$trustMark]),
            'Resolved Trust Marks',
        );

        $this->assertNotNull($row);
        $this->assertNull($row->getWarning());
    }


    public function testShowsDynamicTrustMarks(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_DYNAMIC_TRUST_MARKS => [
                    'trust-mark-type' => 'https://tmi.example.org/',
                ],
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_DYNAMIC_TRUST_MARKS,
        );

        $this->assertNotNull($row);
        $this->assertSame(['trust-mark-type' => ['https://tmi.example.org/']], $row->getValue());
    }


    public function testDescribesTrustMarkStatusPolicy(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_TRUST_MARK_STATUS_ENDPOINT_USAGE_POLICY =>
                    TrustMarkStatusEndpointUsagePolicyEnum::NotUsed,
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_TRUST_MARK_STATUS_ENDPOINT_USAGE_POLICY,
        );

        $this->assertNotNull($row);
        $this->assertSame('Not used', $row->getValue());
        // Built from message IDs, so it must stay translatable.
        $this->assertSame(ConfigOverviewValueTypeEnum::Text, $row->getValueType());
    }


    public function testNormalizesParticipationLimits(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS => [
                    'https://ta.example.org/' => [
                        'one_of' => ['type-a', 'type-b'],
                        'all_of' => [],
                    ],
                    // Trust Anchor with no usable limits is dropped.
                    'https://ta2.example.org/' => [],
                ],
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS,
        );

        $this->assertNotNull($row);
        $this->assertSame(
            [
                'https://ta.example.org/' => ['one_of' => ['type-a', 'type-b'], 'all_of' => []],
                'https://ta2.example.org/' => [],
            ],
            $row->getValue(),
        );
        $this->assertNull($row->getWarning());
    }


    /**
     * Warnings must be whole sentences from the catalog. Interpolating identifiers into them would
     * produce a string gettext can never match, leaving the warning English everywhere.
     */
    public function testParticipationLimitWarningsAreWholeCatalogSentences(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS => [
                    'https://ta.example.org/' => ['any_of' => 'not-a-list'],
                ],
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS,
        );

        $this->assertNotNull($row);
        $warning = (string)$row->getWarning();
        $this->assertNotEmpty($warning);
        $this->assertStringNotContainsString('any_of', $warning);
        $this->assertStringNotContainsString('https://ta.example.org/', $warning);
    }


    /**
     * FederationParticipationValidator calls LimitsEnum::from() on the raw map, so an unrecognized
     * limit identifier fails at runtime. Dropping it here would report "no limit" for a Trust Anchor
     * whose configuration is actually broken.
     */
    public function testSurfacesUnknownParticipationLimitIds(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS => [
                    'https://ta.example.org/' => [
                        'any_of' => ['type-a'],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS,
        );

        $this->assertNotNull($row);
        // The unrecognized rule is still displayed rather than silently dropped.
        $this->assertSame(
            ['https://ta.example.org/' => ['any_of' => ['type-a']]],
            $row->getValue(),
        );
        $this->assertStringContainsString('Unrecognized limit identifiers', (string)$row->getWarning());
    }


    /**
     * The runtime rejects these shapes, so presenting them as an empty (harmless) rule would hide a
     * broken configuration.
     */
    public function testWarnsAboutMalformedParticipationLimitShapes(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS => [
                    'https://ta.example.org/' => ['one_of' => 'not-a-list'],
                ],
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS,
        );

        $this->assertNotNull($row);
        // Kept as configured, so the malformed shape stays visible instead of becoming an empty rule.
        $this->assertSame(
            ['https://ta.example.org/' => ['one_of' => 'not-a-list']],
            $row->getValue(),
        );
        $this->assertStringContainsString('unexpected shape', (string)$row->getWarning());
    }


    public function testWarnsAboutNonArrayParticipationLimitEntry(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS => [
                    'https://ta.example.org/' => 'not-an-array',
                ],
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS,
        );

        $this->assertNotNull($row);
        $this->assertSame(['https://ta.example.org/' => 'not-an-array'], $row->getValue());
        $this->assertStringContainsString('unexpected shape', (string)$row->getWarning());
    }


    public function testShowsTrustChainResolutionLimits(): void
    {
        $sections = $this->buildFederationOverviewBuilder()->build();

        foreach (
            [
                ModuleConfig::OPTION_FEDERATION_MAX_TRUST_CHAIN_DEPTH,
                ModuleConfig::OPTION_FEDERATION_MAX_AUTHORITY_HINTS,
                ModuleConfig::OPTION_FEDERATION_MAX_TRUST_CHAIN_FETCHES,
                ModuleConfig::OPTION_FEDERATION_TRUST_CHAIN_RESOLVE_TIMEOUT,
                ModuleConfig::OPTION_FEDERATION_MAX_FETCH_SIZE_BYTES,
            ] as $configOption
        ) {
            $row = $this->findRowForOption($sections, $configOption);

            $this->assertNotNull($row, "No row found for $configOption");
            $this->assertSame(ConfigOverviewValueTypeEnum::RawText, $row->getValueType());
        }
    }


    public function testRedactsCredentialsInFederationHttpClientOptions(): void
    {
        $sections = $this->buildFederationOverviewBuilder([
            ModuleConfig::OPTION_FEDERATION_HTTP_CLIENT_OPTIONS => [
                'timeout' => 9,
                'proxy' => 'http://user:super-secret-proxy-password@proxy.example.org:8080',
            ],
        ])->build();

        $this->assertStringNotContainsString('super-secret-proxy-password', $this->renderableContent($sections));

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_FEDERATION_HTTP_CLIENT_OPTIONS);
        $this->assertNotNull($row);

        $value = $row->getValue();
        $this->assertIsArray($value);
        $this->assertSame(9, $value['timeout']);
        $this->assertSame('(not shown)', $value['proxy']);
    }


    public function testWarnsWhenFederationTlsVerificationIsDisabled(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_HTTP_CLIENT_OPTIONS => ['verify' => false],
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_HTTP_CLIENT_OPTIONS,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('man-in-the-middle', (string)$row->getWarning());
    }


    public function testNeverExposesCacheAdapterArguments(): void
    {
        $sections = $this->buildFederationOverviewBuilder([
            ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER_ARGUMENTS => [
                'memcached://user:super-secret-password@localhost',
            ],
        ])->build();

        $this->assertStringNotContainsString('super-secret-password', $this->renderableContent($sections));
    }


    public function testNotesWhenNoFederationCacheAdapterIsConfigured(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER => null,
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('recommended in production', (string)$row->getNote());
    }


    public function testRendersDurationsIncludingYears(): void
    {
        $row = $this->findRowForOption(
            $this->buildFederationOverviewBuilder([
                ModuleConfig::OPTION_FEDERATION_ENTITY_STATEMENT_DURATION => 'P1Y',
            ])->build(),
            ModuleConfig::OPTION_FEDERATION_ENTITY_STATEMENT_DURATION,
        );

        $this->assertNotNull($row);
        $this->assertSame('1 year (P1Y)', $row->getValue());
    }


    public function testShowsOptionalEntityMetadata(): void
    {
        $sections = $this->buildFederationOverviewBuilder([
            ModuleConfig::OPTION_DISPLAY_NAME => 'Foo display name',
            ModuleConfig::OPTION_INFORMATION_URI => null,
        ])->build();

        $displayNameRow = $this->findRowForOption($sections, ModuleConfig::OPTION_DISPLAY_NAME);
        $this->assertNotNull($displayNameRow);
        $this->assertSame('Foo display name', $displayNameRow->getValue());
        $this->assertSame(ConfigOverviewValueTypeEnum::RawText, $displayNameRow->getValueType());

        $informationUriRow = $this->findRowForOption($sections, ModuleConfig::OPTION_INFORMATION_URI);
        $this->assertNotNull($informationUriRow);
        $this->assertSame('N/A', $informationUriRow->getValue());
        // The placeholder is UI text, so it stays translatable.
        $this->assertSame(ConfigOverviewValueTypeEnum::Text, $informationUriRow->getValueType());
    }


    /**
     * A malformed option must be reported on its own row rather than take the screen down.
     *
     * Every one of these values throws out of the getter which reads it - SimpleSAMLphp asserts the
     * type at read time, not at load time - and this screen is the one an administrator opens to find
     * out which option is wrong. Building the row outside guardRow() therefore turned a typo into a
     * 500 on the only page that could have explained it.
     */
    #[DataProvider('malformedOptionProvider')]
    public function testReportsAMalformedOptionInPlace(string $option, mixed $value): void
    {
        $sections = $this->buildFederationOverviewBuilder([$option => $value])->build();

        $row = $this->findRowForOption($sections, $option);

        $this->assertNotNull($row, sprintf('No row displays %s.', $option));
        $this->assertNotNull($row->getWarning(), sprintf('%s is not reported on its row.', $option));
    }


    /**
     * A malformed federation switch is one problem, not two.
     *
     * getFederationTrustAnchors() reads OPTION_FEDERATION_ENABLED to decide whether an empty list is
     * an error, so it throws for a malformed switch as well. Attributing that to the Trust Anchors
     * option would send an administrator looking for a second fault which does not exist.
     */
    public function testDoesNotBlameTrustAnchorsForAMalformedFederationSwitch(): void
    {
        $sections = $this->buildFederationOverviewBuilder([
            ModuleConfig::OPTION_FEDERATION_ENABLED => 'yes',
            ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS => [],
        ])->build();

        $switchRow = $this->findRowForOption($sections, ModuleConfig::OPTION_FEDERATION_ENABLED);
        $this->assertNotNull($switchRow);
        $this->assertNotNull($switchRow->getWarning(), 'The malformed switch is not reported.');

        $trustAnchorsRow = $this->findRowForOption($sections, ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS);
        $this->assertNotNull($trustAnchorsRow);
        $this->assertNull(
            $trustAnchorsRow->getWarning(),
            'The malformed switch is reported a second time as a Trust Anchors failure.',
        );
    }


    /**
     * The provider above names the options whose warning text is worth asserting; this covers every
     * option the screen displays, including ones added after it was written.
     */
    public function testNoDisplayedOptionCanTakeTheScreenDown(): void
    {
        $this->assertNoDisplayedOptionCanThrow(
            fn(array $overrides): FederationOverviewBuilder => $this->buildFederationOverviewBuilder(
                $overrides,
            ),
        );
    }


    /**
     * @return array<string, array{0: string, 1: mixed}>
     */
    public static function malformedOptionProvider(): array
    {
        return [
            'federation enabled is not a boolean' => [ModuleConfig::OPTION_FEDERATION_ENABLED, 'yes'],
            'keywords are not an array' => [ModuleConfig::OPTION_KEYWORDS, 'not-an-array'],
            'contacts are not an array' => [ModuleConfig::OPTION_CONTACTS, 'not-an-array'],
            'organization name is not a string' => [ModuleConfig::OPTION_ORGANIZATION_NAME, 123],
            'logo uri is not a string' => [ModuleConfig::OPTION_LOGO_URI, 123],
            'entity statement duration is not a duration' => [
                ModuleConfig::OPTION_FEDERATION_ENTITY_STATEMENT_DURATION,
                'not-a-duration',
            ],
            'authority hints are not an array' => [
                ModuleConfig::OPTION_FEDERATION_AUTHORITY_HINTS,
                'not-an-array',
            ],
            'trust mark tokens are not an array' => [
                ModuleConfig::OPTION_FEDERATION_TRUST_MARK_TOKENS,
                'not-an-array',
            ],
            'dynamic trust marks are not an array' => [
                ModuleConfig::OPTION_FEDERATION_DYNAMIC_TRUST_MARKS,
                'not-an-array',
            ],
            'participation limits are not an array' => [
                ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS,
                'not-an-array',
            ],
            'max trust chain depth is not an integer' => [
                ModuleConfig::OPTION_FEDERATION_MAX_TRUST_CHAIN_DEPTH,
                'deep',
            ],
            'max authority hints is not an integer' => [
                ModuleConfig::OPTION_FEDERATION_MAX_AUTHORITY_HINTS,
                'many',
            ],
            'max trust chain fetches is not an integer' => [
                ModuleConfig::OPTION_FEDERATION_MAX_TRUST_CHAIN_FETCHES,
                'lots',
            ],
            'resolve timeout is not an integer' => [
                ModuleConfig::OPTION_FEDERATION_TRUST_CHAIN_RESOLVE_TIMEOUT,
                'soon',
            ],
            'max fetch size is not an integer' => [
                ModuleConfig::OPTION_FEDERATION_MAX_FETCH_SIZE_BYTES,
                'big',
            ],
            'cache adapter is not a string' => [ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER, 123],
            'cache adapter arguments are not an array' => [
                ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER_ARGUMENTS,
                'not-an-array',
            ],
            'fetched cache duration is not a duration' => [
                ModuleConfig::OPTION_FEDERATION_CACHE_MAX_DURATION_FOR_FETCHED,
                'not-a-duration',
            ],
            'produced cache duration is not a duration' => [
                ModuleConfig::OPTION_FEDERATION_CACHE_DURATION_FOR_PRODUCED,
                'not-a-duration',
            ],
            'http client options are not an array' => [
                ModuleConfig::OPTION_FEDERATION_HTTP_CLIENT_OPTIONS,
                'not-an-array',
            ],
        ];
    }
}

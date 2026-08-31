<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\AbstractOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\Section;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\VciOverviewBuilder;
use SimpleSAML\Module\oidc\Codebooks\ConfigOverviewValueTypeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\AddressPinningModeEnum;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

#[CoversClass(VciOverviewBuilder::class)]
#[CoversClass(AbstractOverviewBuilder::class)]
#[AllowMockObjectsWithoutExpectations]
class VciOverviewBuilderTest extends TestCase
{
    use OverviewTestTrait;
    use VciOverviewTestTrait;


    /**
     * A minimal but realistic credential configuration, shaped like the one in the config template.
     */
    protected static function credentialConfiguration(): array
    {
        return [
            'ResearchAndScholarshipCredentialJwtVcJson' => [
                'format' => 'jwt_vc_json',
                'scope' => 'ResearchAndScholarshipCredentialJwtVcJson',
                'credential_metadata' => [
                    'display' => [
                        ['name' => 'Research and Scholarship', 'locale' => 'en-US'],
                    ],
                    'claims' => [
                        ['path' => ['credentialSubject', 'eduPersonPrincipalName'], 'mandatory' => true],
                        ['path' => ['credentialSubject', 'mail']],
                    ],
                ],
            ],
        ];
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(VciOverviewBuilder::class, $this->buildVciOverviewBuilder());
    }


    public function testCanBuildSections(): void
    {
        $sections = $this->buildVciOverviewBuilder()->build();

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
            $this->buildVciOverviewBuilder()->build(),
        );

        $this->assertSame($anchors, array_unique($anchors));
    }


    public function testEveryRowHasALabel(): void
    {
        foreach ($this->flattenRows($this->buildVciOverviewBuilder()->build()) as $row) {
            $this->assertNotEmpty($row->getLabel());
        }
    }


    public function testNotesWhenVciIsDisabled(): void
    {
        $disabledRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder([ModuleConfig::OPTION_VCI_ENABLED => false])->build(),
            ModuleConfig::OPTION_VCI_ENABLED,
        );
        $this->assertNotNull($disabledRow);
        $this->assertSame('No', $disabledRow->getValue());
        $this->assertStringContainsString('inert', (string)$disabledRow->getNote());
        // Nothing is being issued, so there is nothing to warn about yet.
        $this->assertNull($disabledRow->getWarning());

        $enabledRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder([ModuleConfig::OPTION_VCI_ENABLED => true])->build(),
            ModuleConfig::OPTION_VCI_ENABLED,
        );
        $this->assertNotNull($enabledRow);
        $this->assertSame('Yes', $enabledRow->getValue());
        $this->assertNull($enabledRow->getNote());
    }


    /**
     * The experimental status is stated in the documentation and in the distributed configuration, but
     * neither is necessarily where the person who switched this on is looking. Once credentials are
     * being put into wallets, a later release may be unable to keep them verifiable, so the screen has
     * to say so itself.
     */
    public function testWarnsThatIssuanceIsExperimentalOnceItIsEnabled(): void
    {
        $enabledRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder([ModuleConfig::OPTION_VCI_ENABLED => true])->build(),
            ModuleConfig::OPTION_VCI_ENABLED,
        );

        $this->assertNotNull($enabledRow);
        $warning = (string)$enabledRow->getWarning();
        $this->assertStringContainsString('experimental', $warning);
        $this->assertStringContainsString('production', $warning);
        // No specification version is claimed anywhere any more, so none may reappear here either.
        $this->assertStringNotContainsString('draft', strtolower($warning));
    }


    public function testBuildsCredentialConfigurationDetail(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => self::credentialConfiguration(),
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                    'ResearchAndScholarshipCredentialJwtVcJson' => [
                        ['eduPersonPrincipalName' => ['credentialSubject', 'eduPersonPrincipalName']],
                        ['mail' => ['credentialSubject', 'mail']],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);
        $this->assertSame(ConfigOverviewValueTypeEnum::CredentialConfigurations, $row->getValueType());

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);
        $this->assertCount(1, $configurations);

        $configuration = $configurations[0];
        $this->assertSame('ResearchAndScholarshipCredentialJwtVcJson', $configuration['id']);
        $this->assertSame('jwt_vc_json', $configuration['format']);
        $this->assertTrue($configuration['isFormatSupported']);
        $this->assertSame('ResearchAndScholarshipCredentialJwtVcJson', $configuration['scope']);
        $this->assertSame(['Research and Scholarship'], $configuration['displayNames']);
        $this->assertSame(
            ['credentialSubject.eduPersonPrincipalName', 'credentialSubject.mail'],
            $configuration['claimPaths'],
        );
        $this->assertSame(
            [
                [
                    'attribute' => 'eduPersonPrincipalName',
                    'path' => 'credentialSubject.eduPersonPrincipalName',
                    'ineffectiveReason' => null,
                    'isEffective' => true,
                    'hasIgnoredPairs' => false,
                ],
                [
                    'attribute' => 'mail',
                    'path' => 'credentialSubject.mail',
                    'ineffectiveReason' => null,
                    'isEffective' => true,
                    'hasIgnoredPairs' => false,
                ],
            ],
            $configuration['attributeMappings'],
        );
        // No JSON-LD context configured for this one.
        $this->assertNull($configuration['jsonLdContextUrl']);
    }


    /**
     * CredentialIssuerCredentialController skips a mapping whose path is not among the declared
     * claim paths, so the screen must not present it as effective.
     */
    public function testMarksMappingsIssuanceWillSkip(): void
    {
        $sections = $this->buildVciOverviewBuilder([
            ModuleConfig::OPTION_VCI_ENABLED => true,
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => self::credentialConfiguration(),
            ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                'ResearchAndScholarshipCredentialJwtVcJson' => [
                    // Declared by the credential configuration.
                    ['mail' => ['credentialSubject', 'mail']],
                    // Not declared, so issuance drops it.
                    ['telephoneNumber' => ['credentialSubject', 'telephoneNumber']],
                ],
            ],
        ])->build();

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED);
        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);

        $mappingsByAttribute = array_column($configurations[0]['attributeMappings'], null, 'attribute');

        $this->assertTrue($mappingsByAttribute['mail']['isEffective']);
        $this->assertFalse($mappingsByAttribute['telephoneNumber']['isEffective']);
        $this->assertSame('notDeclared', $mappingsByAttribute['telephoneNumber']['ineffectiveReason']);

        $this->assertStringContainsString('never reaches the credential', (string)$row->getWarning());
    }


    public function testDoesNotWarnWhenEveryMappingIsEffective(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => self::credentialConfiguration(),
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                    'ResearchAndScholarshipCredentialJwtVcJson' => [
                        ['mail' => ['credentialSubject', 'mail']],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);
        $this->assertNull($row->getWarning());
    }


    /**
     * Issuance reads only key()/current() of a map entry, so any further pair is ignored. Listing
     * them all would claim attributes are issued when they never are.
     */
    public function testShowsOnlyTheMappingPairIssuanceUses(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => self::credentialConfiguration(),
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                    'ResearchAndScholarshipCredentialJwtVcJson' => [
                        [
                            'mail' => ['credentialSubject', 'mail'],
                            // Ignored during issuance.
                            'eduPersonPrincipalName' => ['credentialSubject', 'eduPersonPrincipalName'],
                        ],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);

        $mappings = $configurations[0]['attributeMappings'];
        $this->assertCount(1, $mappings);
        $this->assertSame('mail', $mappings[0]['attribute']);
        $this->assertTrue($mappings[0]['hasIgnoredPairs']);

        $this->assertStringContainsString('only the first pair', (string)$row->getWarning());
    }


    public function testSkipsMappingEntriesWithNonStringAttributeName(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => self::credentialConfiguration(),
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                    'ResearchAndScholarshipCredentialJwtVcJson' => [
                        [['credentialSubject', 'mail']],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);
        $this->assertSame([], $configurations[0]['attributeMappings']);
    }


    /**
     * getVciCredentialJsonLdContext() throws for a non-array value, and it sits outside the
     * credential configuration guard.
     */
    public function testReportsMalformedJsonLdContextInPlace(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT => 'not-an-array',
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('written to the SimpleSAMLphp log', (string)$row->getWarning());
        $this->assertNull($row->getNote());
    }


    /**
     * CredentialIssuerCredentialController can only issue jwt_vc_json, dc+sd-jwt and vc+sd-jwt, and
     * rejects a configuration whose format is missing, so an unsupported one must not look valid.
     */
    public function testFlagsUnsupportedCredentialFormat(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'NoFormat' => ['scope' => 'NoFormat'],
                    'BogusFormat' => ['format' => 'made_up_format'],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);
        $this->assertFalse($configurations[0]['isFormatSupported']);
        $this->assertFalse($configurations[1]['isFormatSupported']);

        $this->assertStringContainsString('unsupported format', (string)$row->getWarning());
    }


    /**
     * Issuance filters a mapping path down to its string segments and writes at what remains, so the
     * screen must name the path the credential ends up with, not the one that was configured.
     */
    public function testRendersMappingPathWithoutNonStringSegments(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'JwtVcJsonCredential' => [
                        'format' => 'jwt_vc_json',
                        'credential_metadata' => [
                            // Declared with the non-string segment already absent, which is what
                            // issuance compares the filtered mapping path against.
                            'claims' => [['path' => ['credentialSubject', 'mail']]],
                        ],
                    ],
                ],
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                    'JwtVcJsonCredential' => [
                        ['mail' => ['credentialSubject', 'mail', 0]],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);

        $mapping = $configurations[0]['attributeMappings'][0];

        // Not 'credentialSubject.mail.0': the 0 never reaches setNestedValue().
        $this->assertSame('credentialSubject.mail', $mapping['path']);
        // With the trailing integer dropped the path matches a declared one, so it does take effect.
        $this->assertTrue($mapping['isEffective']);
    }


    /**
     * array_filter() preserves keys, so a non-string segment before the end leaves a gap in them and
     * the in_array() comparison against the declared paths fails. Issuance rejects such a mapping, so
     * the screen must not present it as effective, even though the rendered path looks declared.
     */
    public function testMarksMappingWithInterruptedPathAsIneffective(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'JwtVcJsonCredential' => [
                        'format' => 'jwt_vc_json',
                        'credential_metadata' => [
                            'claims' => [['path' => ['credentialSubject', 'mail']]],
                        ],
                    ],
                ],
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                    'JwtVcJsonCredential' => [
                        ['mail' => ['credentialSubject', 0, 'mail']],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);

        $mapping = $configurations[0]['attributeMappings'][0];

        $this->assertSame('credentialSubject.mail', $mapping['path']);
        $this->assertSame('notDeclared', $mapping['ineffectiveReason']);
    }


    /**
     * A declared path is handed to issuance unchanged, so it is shown as configured even when a
     * segment could never form part of a usable path.
     */
    public function testRendersDeclaredClaimPathAsConfigured(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'JwtVcJsonCredential' => [
                        'format' => 'jwt_vc_json',
                        'credential_metadata' => [
                            'claims' => [['path' => ['credentialSubject', 0, 'mail']]],
                        ],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);

        $this->assertSame(['credentialSubject.0.mail'], $configurations[0]['claimPaths']);
    }


    /**
     * For jwt_vc_json the controller writes at the configured path but serializes only the
     * 'credentialSubject' branch, so a path rooted elsewhere is written and immediately dropped.
     */
    public function testMarksJwtVcJsonMappingOutsideCredentialSubjectAsIneffective(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'JwtVcJsonCredential' => [
                        'format' => 'jwt_vc_json',
                        'credential_metadata' => [
                            'claims' => [
                                ['path' => ['credentialSubject', 'mail']],
                                ['path' => ['mail']],
                            ],
                        ],
                    ],
                ],
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                    'JwtVcJsonCredential' => [
                        ['mail' => ['credentialSubject', 'mail']],
                        // Declared, and matches a valid claim path, but dropped at serialization.
                        ['secondaryMail' => ['mail']],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);

        $mappingsByAttribute = array_column($configurations[0]['attributeMappings'], null, 'attribute');

        $this->assertTrue($mappingsByAttribute['mail']['isEffective']);
        $this->assertFalse($mappingsByAttribute['secondaryMail']['isEffective']);

        // The reason matters: this path IS declared, it is discarded at serialization. Saying it was
        // not declared would send an administrator looking in the wrong place.
        $this->assertSame('droppedForFormat', $mappingsByAttribute['secondaryMail']['ineffectiveReason']);
    }


    /**
     * The SD-JWT formats do not have that restriction: dc+sd-jwt uses the path as-is.
     */
    public function testAcceptsSdJwtMappingOutsideCredentialSubject(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'SdJwtCredential' => [
                        'format' => 'dc+sd-jwt',
                        'credential_metadata' => [
                            'claims' => [['path' => ['mail']]],
                        ],
                    ],
                ],
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                    'SdJwtCredential' => [['mail' => ['mail']]],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);
        $this->assertTrue($configurations[0]['attributeMappings'][0]['isEffective']);
        // dc+sd-jwt discloses at the configured path, so it is shown unchanged.
        $this->assertSame('mail', $configurations[0]['attributeMappings'][0]['path']);
        $this->assertNull($row->getWarning());
    }


    /**
     * vc+sd-jwt does root a disclosure under 'credentialSubject' when the parent path does not
     * already mention it, so the effective path differs from the configured one.
     */
    public function testRootsVcSdJwtDisclosurePathUnderCredentialSubject(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'VcSdJwtCredential' => [
                        'format' => 'vc+sd-jwt',
                        'credential_metadata' => [
                            'claims' => [
                                ['path' => ['mail']],
                                ['path' => ['credentialSubject', 'givenName']],
                            ],
                        ],
                    ],
                ],
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                    'VcSdJwtCredential' => [
                        ['mail' => ['mail']],
                        ['givenName' => ['credentialSubject', 'givenName']],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);

        $mappingsByAttribute = array_column($configurations[0]['attributeMappings'], null, 'attribute');

        // Configured as 'mail', but the disclosure lands under credentialSubject.
        $this->assertSame('credentialSubject.mail', $mappingsByAttribute['mail']['path']);
        // Already rooted there, so it is left alone rather than doubled up.
        $this->assertSame('credentialSubject.givenName', $mappingsByAttribute['givenName']['path']);

        // Both are declared and vc+sd-jwt has no credentialSubject restriction of its own.
        $this->assertTrue($mappingsByAttribute['mail']['isEffective']);
        $this->assertTrue($mappingsByAttribute['givenName']['isEffective']);
    }


    public function testLinksJsonLdContextWhenConfigured(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => self::credentialConfiguration(),
                ModuleConfig::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT => [
                    'ResearchAndScholarshipCredentialJwtVcJson' => ['@context' => []],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);
        // Routes is mocked, so the URL is an empty string rather than null: what matters is that a
        // context was found and a link was therefore built.
        $this->assertNotNull($configurations[0]['jsonLdContextUrl']);
    }


    /**
     * A non-array credential configuration makes getVciCredentialConfiguration() throw, which must
     * be reported in place rather than take the screen down.
     */
    public function testReportsMalformedCredentialConfigurationInPlace(): void
    {
        $sections = $this->buildVciOverviewBuilder([
            ModuleConfig::OPTION_VCI_ENABLED => true,
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => ['Broken' => 'not-an-array'],
        ])->build();

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED);

        $this->assertNotNull($row);
        $this->assertSame([], $row->getValue());
        $this->assertStringContainsString('written to the SimpleSAMLphp log', (string)$row->getWarning());
        // The descriptive note must not contradict the empty value.
        $this->assertNull($row->getNote());
    }


    public function testDoesNotExposeMalformedCredentialConfigurationDetail(): void
    {
        $sections = $this->buildVciOverviewBuilder([
            ModuleConfig::OPTION_VCI_ENABLED => true,
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => ['Broken' => 'super-secret-looking-value'],
        ])->build();

        $this->assertStringNotContainsString('super-secret-looking-value', $this->renderableContent($sections));
    }


    public function testWarnsWhenNonRegisteredClientsHaveNoAllowedPrefixes(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS => true,
                ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS => [],
            ])->build(),
            ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('will be rejected', (string)$row->getWarning());
    }


    /**
     * ClientRedirectUriRule casts each configured prefix with (string), so a null becomes an empty
     * prefix and str_starts_with() then matches every redirect URI. Filtering non-strings out would
     * make the screen claim the opposite of what the runtime does.
     */
    public function testMirrorsRuntimeNormalizationOfRedirectPrefixes(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS => true,
                ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS => [
                    'openid-credential-offer://',
                    null,
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS,
        );

        $this->assertNotNull($row);
        // The null is shown as the empty prefix it actually becomes, not dropped.
        $this->assertSame(['openid-credential-offer://', ''], $row->getValue());
        $this->assertStringContainsString('redirected anywhere', (string)$row->getWarning());
    }


    /**
     * The runtime does not skip a nested array: casting it yields the literal 'Array', so a redirect
     * URI starting with that text would be accepted. Dropping it here would hide that.
     */
    public function testShowsNestedArrayPrefixAsTheRuntimeCastsIt(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS => true,
                ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS => [
                    ['nested-array'],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS,
        );

        $this->assertNotNull($row);
        $this->assertSame(['Array'], $row->getValue());
        $this->assertStringContainsString('not a string', (string)$row->getWarning());
    }


    public function testDoesNotWarnAboutPrefixesWhenNonRegisteredClientsAreDisallowed(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS => false,
                ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS => [],
            ])->build(),
            ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS,
        );

        $this->assertNotNull($row);
        $this->assertNull($row->getWarning());
    }


    public function testNotesIssuerStateTtlFallback(): void
    {
        $fallbackRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder()->build(),
            ModuleConfig::OPTION_VCI_ISSUER_STATE_TTL,
        );
        $this->assertNotNull($fallbackRow);
        $this->assertStringContainsString('Authorization Code TTL', (string)$fallbackRow->getNote());
        // tests/config sets the authorization code TTL to PT10M.
        $this->assertSame('10 minutes (PT10M)', $fallbackRow->getValue());

        $configuredRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder([ModuleConfig::OPTION_VCI_ISSUER_STATE_TTL => 'PT30M'])->build(),
            ModuleConfig::OPTION_VCI_ISSUER_STATE_TTL,
        );
        $this->assertNotNull($configuredRow);
        $this->assertSame('30 minutes (PT30M)', $configuredRow->getValue());
    }


    public function testNotesNonceTtlFallback(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder()->build(),
            ModuleConfig::OPTION_VCI_NONCE_TTL,
        );

        $this->assertNotNull($row);
        $this->assertSame('5 minutes (PT5M)', $row->getValue());
        $this->assertStringContainsString('falls back to 5 minutes', (string)$row->getNote());
    }


    /**
     * The credential offer endpoint is gated by the module API master switch, which lives on the
     * protocol screen, so an inconsistent pair must be called out here.
     */
    public function testWarnsWhenCredentialOfferEndpointIsEnabledWithoutTheApi(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_API_ENABLED => false,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED => true,
            ])->build(),
            ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('module API itself is disabled', (string)$row->getWarning());
    }


    /**
     * VciCredentialOfferApiController rejects every request unless VCI is enabled, so the endpoint
     * must not be listed as served on the strength of the API switches alone.
     */
    public function testDoesNotListOfferEndpointWhenVciIsDisabled(): void
    {
        $labels = fn(array $sections): array => array_map(
            fn($row): string => $row->getLabel(),
            $this->flattenRows($sections),
        );

        $this->assertNotContains(
            'Credential Offer (API)',
            $labels($this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => false,
                ModuleConfig::OPTION_API_ENABLED => true,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED => true,
            ])->build()),
        );

        $this->assertContains(
            'Credential Offer (API)',
            $labels($this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_API_ENABLED => true,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED => true,
            ])->build()),
        );
    }


    /**
     * Both CredentialIssuerCredentialController and NonceController throw a forbidden response from
     * their constructor while VCI is off, so neither endpoint may be presented as usable.
     */
    public function testMarksCredentialAndNonceEndpointsUnservedWhenVciIsDisabled(): void
    {
        $disabled = $this->buildVciOverviewBuilder([ModuleConfig::OPTION_VCI_ENABLED => false])->build();

        foreach (['Credential', 'Nonce'] as $label) {
            $row = $this->findRowByLabel($disabled, $label);

            $this->assertNotNull($row, "Missing row for $label");
            $this->assertStringContainsString(
                'Not served, since Verifiable Credential Issuance is disabled.',
                (string)$row->getNote(),
                "Endpoint $label is presented as served while VCI is disabled",
            );
        }

        $enabled = $this->buildVciOverviewBuilder([ModuleConfig::OPTION_VCI_ENABLED => true])->build();

        foreach (['Credential', 'Nonce'] as $label) {
            $row = $this->findRowByLabel($enabled, $label);

            $this->assertNotNull($row, "Missing row for $label");
            $this->assertNull($row->getNote(), "Endpoint $label is marked unserved while VCI is enabled");
        }
    }


    /**
     * A malformed api_enabled belongs to the protocol screen; it must not be reported as a failure
     * of the credential offer endpoint option, whose own value is still readable.
     */
    public function testDoesNotBlameOfferEndpointForMalformedApiSwitch(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_API_ENABLED => 'nope',
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED => true,
            ])->build(),
            ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED,
        );

        $this->assertNotNull($row);
        // Its own value is readable and is reported accurately.
        $this->assertSame('Yes', $row->getValue());
        $this->assertStringNotContainsString('written to the SimpleSAMLphp log', (string)$row->getWarning());
    }


    public function testDoesNotWarnWhenApiAndOfferEndpointAgree(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_API_ENABLED => true,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED => true,
            ])->build(),
            ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED,
        );

        $this->assertNotNull($row);
        $this->assertNull($row->getWarning());
    }


    public function testShowsEmailAttributeConfiguration(): void
    {
        $sections = $this->buildVciOverviewBuilder([
            ModuleConfig::OPTION_DEFAULT_USERS_EMAIL_ATTRIBUTE_NAME => 'mail',
            ModuleConfig::OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP => [
                'example-userpass' => 'emailAddress',
            ],
        ])->build();

        $defaultRow = $this->findRowForOption($sections, ModuleConfig::OPTION_DEFAULT_USERS_EMAIL_ATTRIBUTE_NAME);
        $this->assertNotNull($defaultRow);
        $this->assertSame('mail', $defaultRow->getValue());

        $mapRow = $this->findRowForOption(
            $sections,
            ModuleConfig::OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP,
        );
        $this->assertNotNull($mapRow);
        $this->assertSame(['example-userpass' => ['emailAddress']], $mapRow->getValue());
    }


    /**
     * A malformed JSON-LD or attribute-map option must be reported on its own row, without emptying
     * the otherwise valid credential configurations and blaming the wrong setting.
     */
    public function testIsolatesJsonLdFailureFromCredentialConfigurations(): void
    {
        $sections = $this->buildVciOverviewBuilder([
            ModuleConfig::OPTION_VCI_ENABLED => true,
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => self::credentialConfiguration(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT => 'not-an-array',
        ])->build();

        $configurationsRow = $this->findRowForOption(
            $sections,
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );
        $this->assertNotNull($configurationsRow);
        $this->assertCount(1, $configurationsRow->getValue());
        $this->assertNull($configurationsRow->getWarning());

        $jsonLdRow = $this->findRowForOption($sections, ModuleConfig::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT);
        $this->assertNotNull($jsonLdRow);
        $this->assertNotNull($jsonLdRow->getWarning());
    }


    public function testIsolatesAttributeMapFailureFromCredentialConfigurations(): void
    {
        $sections = $this->buildVciOverviewBuilder([
            ModuleConfig::OPTION_VCI_ENABLED => true,
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => self::credentialConfiguration(),
            ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => 'not-an-array',
        ])->build();

        $configurationsRow = $this->findRowForOption(
            $sections,
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );
        $this->assertNotNull($configurationsRow);
        $this->assertCount(1, $configurationsRow->getValue());

        $mapRow = $this->findRowForOption(
            $sections,
            ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP,
        );
        $this->assertNotNull($mapRow);
        $this->assertStringContainsString('written to the SimpleSAMLphp log', (string)$mapRow->getWarning());
    }


    /**
     * getUsersEmailAttributeNameForAuthSourceId() only honours a string and otherwise falls back to
     * the default, so a non-string entry is not an override and must not be shown as one.
     */
    public function testIgnoresNonStringEmailAttributeOverrides(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP => [
                    'example-userpass' => 'emailAddress',
                    'broken-source' => ['not', 'a', 'string'],
                ],
            ])->build(),
            ModuleConfig::OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP,
        );

        $this->assertNotNull($row);
        $this->assertSame(['example-userpass' => ['emailAddress']], $row->getValue());
        $this->assertStringContainsString('falls back to the default', (string)$row->getWarning());
    }

    /**
     * These options were not read by the previous template, so the reworked screen must not start
     * failing on values it newly evaluates.
     *
     * @param array $overrides
     * @param string $configOption
     */
    #[DataProvider('malformedOptionProvider')]
    public function testSurvivesMalformedOption(array $overrides, string $configOption): void
    {
        $sections = $this->buildVciOverviewBuilder($overrides)->build();

        $row = $this->findRowForOption($sections, $configOption);

        $this->assertNotNull($row, "No row found for $configOption");
        $this->assertNotNull($row->getWarning(), "Expected a warning for malformed $configOption");
        $this->assertNull($row->getNote());
    }


    public static function malformedOptionProvider(): array
    {
        return [
            'redirect prefixes not an array' => [
                [ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS => 'nope'],
                ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS,
            ],
            'allow non-registered not a bool' => [
                [ModuleConfig::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS => 'nope'],
                ModuleConfig::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS,
            ],
            'issuer state ttl not a duration' => [
                [ModuleConfig::OPTION_VCI_ISSUER_STATE_TTL => 'not-a-duration'],
                ModuleConfig::OPTION_VCI_ISSUER_STATE_TTL,
            ],
            'nonce ttl not a duration' => [
                [ModuleConfig::OPTION_VCI_NONCE_TTL => 'not-a-duration'],
                ModuleConfig::OPTION_VCI_NONCE_TTL,
            ],
            'vci enabled not a bool' => [
                [ModuleConfig::OPTION_VCI_ENABLED => 'nope'],
                ModuleConfig::OPTION_VCI_ENABLED,
            ],
            'offer endpoint not a bool' => [
                [ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED => 'nope'],
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED,
            ],
            'email attribute map not an array' => [
                [ModuleConfig::OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP => 'nope'],
                ModuleConfig::OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP,
            ],
        ];
    }


    /**
     * A non-array entry is treated as absent by the runtime, so counting it as a configured document
     * would advertise one whose endpoint returns 404.
     */
    public function testCountsOnlyUsableJsonLdContexts(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT => [
                    'Usable' => ['@context' => []],
                    'Unusable' => 'not-an-array',
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT,
        );

        $this->assertNotNull($row);
        $this->assertSame('1', $row->getValue());
    }


    public function testReportsSignatureKeyPairErrorInPlace(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS => []])->build(),
            ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS,
        );

        $this->assertNotNull($row);
        $this->assertNull($row->getValue());
        $this->assertNotNull($row->getWarning());
    }


    /**
     * Turning pinning off is the one DID setting which weakens a protection rather than merely
     * widening it, so it has to stay visible to whoever opens this screen.
     */
    public function testWarnsWhenDidAddressPinningIsDisabled(): void
    {
        $requiredRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder()->build(),
            ModuleConfig::OPTION_VCI_DID_ADDRESS_PINNING_MODE,
        );

        $this->assertNotNull($requiredRow);
        $this->assertSame(AddressPinningModeEnum::Required->value, $requiredRow->getValue());
        $this->assertNull($requiredRow->getWarning());

        $disabledRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_DID_ADDRESS_PINNING_MODE => AddressPinningModeEnum::Disabled,
            ])->build(),
            ModuleConfig::OPTION_VCI_DID_ADDRESS_PINNING_MODE,
        );

        $this->assertNotNull($disabledRow);
        $this->assertSame(AddressPinningModeEnum::Disabled->value, $disabledRow->getValue());
        $this->assertNotNull($disabledRow->getWarning());
    }


    /**
     * Preferred is refused when the configuration is read, and this screen is what an administrator
     * opens to find out why, so the refusal has to be reported on the row rather than take the page
     * down.
     */
    public function testReportsARefusedDidAddressPinningModeInPlace(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_DID_ADDRESS_PINNING_MODE => AddressPinningModeEnum::Preferred,
            ])->build(),
            ModuleConfig::OPTION_VCI_DID_ADDRESS_PINNING_MODE,
        );

        $this->assertNotNull($row);
        $this->assertNotNull($row->getWarning());
    }


    /**
     * Each exemption is a destination that whoever supplies a DID can send this deployment to.
     */
    public function testWarnsAboutDidDestinationExemptions(): void
    {
        $sections = $this->buildVciOverviewBuilder()->build();

        $hostsRow = $this->findRowForOption(
            $sections,
            ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_HOSTS,
        );
        $this->assertNotNull($hostsRow);
        $this->assertSame([], $hostsRow->getValue());
        $this->assertNull($hostsRow->getWarning());

        $cidrsRow = $this->findRowForOption(
            $sections,
            ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_CIDRS,
        );
        $this->assertNotNull($cidrsRow);
        $this->assertSame([], $cidrsRow->getValue());
        $this->assertNull($cidrsRow->getWarning());

        $exemptedSections = $this->buildVciOverviewBuilder([
            ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_HOSTS => ['wallet.internal.example'],
            ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_CIDRS => ['10.1.2.3/32'],
        ])->build();

        $exemptedHostsRow = $this->findRowForOption(
            $exemptedSections,
            ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_HOSTS,
        );
        $this->assertNotNull($exemptedHostsRow);
        $this->assertSame(['wallet.internal.example'], $exemptedHostsRow->getValue());
        $this->assertNotNull($exemptedHostsRow->getWarning());

        $exemptedCidrsRow = $this->findRowForOption(
            $exemptedSections,
            ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_CIDRS,
        );
        $this->assertNotNull($exemptedCidrsRow);
        $this->assertSame(['10.1.2.3/32'], $exemptedCidrsRow->getValue());
        $this->assertNotNull($exemptedCidrsRow->getWarning());
    }


    /**
     * An unusable range would otherwise be shown as a working exemption.
     */
    public function testReportsAnUnusableDidAddressRangeInPlace(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_CIDRS => ['not-a-range'],
            ])->build(),
            ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_CIDRS,
        );

        $this->assertNotNull($row);
        $this->assertNotNull($row->getWarning());
    }


    public function testNotesWhenNoVciCacheIsConfigured(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder()->build(),
            ModuleConfig::OPTION_VCI_CACHE_ADAPTER,
        );

        $this->assertNotNull($row);
        $this->assertNotNull($row->getNote());
    }


    /**
     * A malformed cache option must be reported on its row rather than take the screen down. The
     * getters only assert the value's type when it is read, and this screen is where an administrator
     * goes to find out that a value is wrong.
     */
    #[DataProvider('malformedCacheOptionProvider')]
    public function testReportsAMalformedCacheOptionInPlace(string $option, mixed $value): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([$option => $value])->build(),
            $option,
        );

        $this->assertNotNull($row);
        $this->assertNotNull($row->getWarning());
    }


    public static function malformedCacheOptionProvider(): array
    {
        return [
            'adapter class is not a string' => [ModuleConfig::OPTION_VCI_CACHE_ADAPTER, 123],
            'adapter arguments are not an array' => [
                ModuleConfig::OPTION_VCI_CACHE_ADAPTER_ARGUMENTS,
                'not-an-array',
            ],
            'cache duration is not a duration' => [
                ModuleConfig::OPTION_VCI_DID_CACHE_MAX_DURATION,
                'not-a-duration',
            ],
        ];
    }


    /**
     * Adapter arguments can carry connection credentials, so the row counts them instead of showing
     * them.
     */
    public function testDoesNotRenderVciCacheAdapterArguments(): void
    {
        $sections = $this->buildVciOverviewBuilder([
            ModuleConfig::OPTION_VCI_CACHE_ADAPTER => ArrayAdapter::class,
            ModuleConfig::OPTION_VCI_CACHE_ADAPTER_ARGUMENTS => ['openidVci', 'super-secret-dsn'],
        ])->build();

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_VCI_CACHE_ADAPTER_ARGUMENTS);
        $this->assertNotNull($row);
        $this->assertSame('2', $row->getValue());

        $this->assertStringNotContainsString('super-secret-dsn', $this->renderableContent($sections));
    }


    /**
     * Covers every option this screen displays, including ones added after this was written.
     */
    public function testNoDisplayedOptionCanTakeTheScreenDown(): void
    {
        $this->assertNoDisplayedOptionCanThrow(
            fn(array $overrides): VciOverviewBuilder => $this->buildVciOverviewBuilder($overrides),
        );
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\AbstractOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\Section;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\VciOverviewBuilder;
use SimpleSAML\Module\oidc\Codebooks\ConfigOverviewValueTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\OpenID\Codebooks\AddressPinningModeEnum;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;
use stdClass;
use Stringable;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * One line is deliberately left uncovered here: the `continue` in `hasMappingFlag()`, which skips
 * a credential configuration carrying no `attributeMappings` array. Neither of its two conditions
 * is reachable through `build()`. The list that method receives is always the one
 * `buildCredentialConfigurationList()` produced, every entry of which is an array, and each of
 * those entries carries whatever `buildAttributeMappings()` returned, which is always an array.
 * The guard is defensive depth against a caller which does not exist.
 */
#[CoversClass(VciOverviewBuilder::class)]
#[CoversClass(AbstractOverviewBuilder::class)]
#[AllowMockObjectsWithoutExpectations]
class VciOverviewBuilderTest extends TestCase
{
    use OverviewTestTrait;
    use VciOverviewTestTrait;


    /**
     * A did:web whose document URL a stock module installation can actually serve, and that URL.
     */
    protected const string DID_WEB_WITH_PATH = 'did:web:example.org:simplesaml:module.php:oidc';

    protected const string DID_WEB_WITH_PATH_URL = 'https://example.org/simplesaml/module.php/oidc/did.json';

    protected const string ISSUER = 'https://issuer.example.org';


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


    public function testShowsTheIssuerIdentityModeAndSaysWhatItMeans(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder()->build(),
            ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE,
        );

        $this->assertNotNull($row);
        $this->assertSame(VciIssuerIdentifierModeEnum::DidJwk->value, $row->getValue());
        $this->assertNotEmpty($row->getNote());
        $this->assertNull($row->getWarning());
    }


    /**
     * The `https` mode is a deliberate way out for verifiers which will not take a DID, but the
     * profile this module claims to follow requires one, so the screen has to say so.
     */
    public function testWarnsThatTheHttpsIssuerIdentityIsNotProfileConformant(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => VciIssuerIdentifierModeEnum::Https,
            ])->build(),
            ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('DIIP', (string)$row->getWarning());
    }


    public function testSaysWhenNoDidDocumentIsPublished(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder()->build(),
            ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER,
        );

        $this->assertNotNull($row);
        $this->assertSame('None configured', $row->getValue());
        $this->assertNull($row->getWarning());
    }


    /**
     * Both URLs are shown, and no warning while they agree.
     */
    public function testShowsWhereTheDidWebIdentifierResolvesTo(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder(
                [
                    ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => VciIssuerIdentifierModeEnum::DidWeb,
                    ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => self::DID_WEB_WITH_PATH,
                ],
                didDocumentUrl: self::DID_WEB_WITH_PATH_URL,
            )->build(),
            ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER,
        );

        $this->assertNotNull($row);
        $this->assertSame(
            [
                'did' => self::DID_WEB_WITH_PATH,
                'resolvesTo' => self::DID_WEB_WITH_PATH_URL,
                'servedAt' => self::DID_WEB_WITH_PATH_URL,
            ],
            $row->getValue(),
        );
        $this->assertNull($row->getWarning());
    }


    /**
     * Comparing hosts alone would not catch this: the path segments decide the URL too, and the bare
     * form asks for one at the web root which SimpleSAMLphp never serves.
     */
    public function testWarnsWhenTheDidWebIdentifierResolvesElsewhere(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder(
                [
                    ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => VciIssuerIdentifierModeEnum::DidWeb,
                    ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => 'did:web:example.org',
                ],
                didDocumentUrl: self::DID_WEB_WITH_PATH_URL,
            )->build(),
            ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('map', (string)$row->getWarning());
    }


    /**
     * The document stays published after the mode moves on, and the row says that is what is
     * happening rather than leaving it looking like a stale setting.
     */
    public function testSaysADidWebDocumentIsStillPublishedAfterTheModeMovedOn(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder(
                [
                    ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => VciIssuerIdentifierModeEnum::DidJwk,
                    ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => self::DID_WEB_WITH_PATH,
                ],
                didDocumentUrl: self::DID_WEB_WITH_PATH_URL,
            )->build(),
            ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER,
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('still', (string)$row->getNote());
        $this->assertNull($row->getWarning());
    }


    public function testSaysNothingHasBeenIssuedYet(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder()->build(),
            'Identities Credentials Were Issued Under',
        );

        $this->assertNotNull($row);
        $this->assertSame('None recorded', $row->getValue());
        $this->assertNull($row->getWarning());
    }


    /**
     * A did:jwk credential carries its own key, so it stays verifiable whatever is configured later.
     * The other two are only resolvable while the deployment still publishes them, and here it does.
     */
    public function testDoesNotWarnAboutIdentitiesWhichAreStillPublished(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder(
                [
                    ModuleConfig::OPTION_ISSUER => self::ISSUER,
                    ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => VciIssuerIdentifierModeEnum::DidWeb,
                    ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => self::DID_WEB_WITH_PATH,
                ],
                [
                    'did:jwk:retired' => VciIssuerIdentifierModeEnum::DidJwk->value,
                    self::ISSUER => VciIssuerIdentifierModeEnum::Https->value,
                    self::DID_WEB_WITH_PATH => VciIssuerIdentifierModeEnum::DidWeb->value,
                ],
                self::DID_WEB_WITH_PATH_URL,
            )->build(),
            'Identities Credentials Were Issued Under',
        );

        $this->assertNotNull($row);
        $this->assertSame(
            ['did:jwk:retired', self::ISSUER, self::DID_WEB_WITH_PATH],
            $row->getValue(),
        );
        $this->assertNull($row->getWarning());
    }


    /**
     * The whole point of recording what was issued under: configuration alone cannot tell anyone that
     * credentials exist which nothing can resolve any more.
     */
    public function testWarnsAboutADidWebIdentityWhichIsNoLongerPublished(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder(
                [],
                ['did:web:retired.example.org' => VciIssuerIdentifierModeEnum::DidWeb->value],
            )->build(),
            'Identities Credentials Were Issued Under',
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('can no longer be verified', (string)$row->getWarning());
    }


    /**
     * An issuer URL identity is no less perishable than a did:web one: credentials issued under it
     * resolve their metadata and their signing key through that URL, so changing the issuer leaves
     * them naming an identity this deployment no longer answers for.
     */
    public function testWarnsAboutAnIssuerUrlIdentityWhichIsNoLongerThisIssuer(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder(
                [ModuleConfig::OPTION_ISSUER => self::ISSUER],
                ['https://old-issuer.example.org' => VciIssuerIdentifierModeEnum::Https->value],
            )->build(),
            'Identities Credentials Were Issued Under',
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('can no longer be verified', (string)$row->getWarning());
    }


    public function testSaysNoStatusListNamesADidWeb(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder()->build(),
            'Identities Status Lists Are Signed Under',
        );

        $this->assertNotNull($row);
        $this->assertSame('None recorded', $row->getValue());
        $this->assertNull($row->getWarning());
    }


    /**
     * The lists name the identifier the deployment still publishes, so there is nothing to act on --
     * only the standing obligation to keep publishing it, which the note states.
     */
    public function testDoesNotWarnAboutStatusListIdentitiesWhichAreStillPublished(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder(
                [ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => self::DID_WEB_WITH_PATH],
                didDocumentUrl: self::DID_WEB_WITH_PATH_URL,
                statusListIssuerIdentifiers: [self::DID_WEB_WITH_PATH],
            )->build(),
            'Identities Status Lists Are Signed Under',
        );

        $this->assertNotNull($row);
        $this->assertSame([self::DID_WEB_WITH_PATH], $row->getValue());
        $this->assertStringContainsString('has to stay', (string)$row->getNote());
        $this->assertNull($row->getWarning());
    }


    /**
     * The case M5c left unreported: credentials are issued under a did:jwk, so the deployment's
     * did:web appears on no credential and the row which answers for credentials has never seen it.
     * Only the lists know it, and only they can say its document is still needed.
     */
    public function testWarnsAboutAStatusListIdentityWhichIsNoLongerPublished(): void
    {
        $sections = $this->buildVciOverviewBuilder(
            [
                ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => VciIssuerIdentifierModeEnum::DidJwk,
                ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => self::DID_WEB_WITH_PATH,
            ],
            didDocumentUrl: self::DID_WEB_WITH_PATH_URL,
            statusListIssuerIdentifiers: ['did:web:retired.example.org'],
        )->build();

        $row = $this->findRowByLabel($sections, 'Identities Status Lists Are Signed Under');

        $this->assertNotNull($row);
        $this->assertStringContainsString('not the configured did:web', (string)$row->getWarning());

        // The credentials row is the one which cannot see this, which is why the new row exists.
        $credentialsRow = $this->findRowByLabel($sections, 'Identities Credentials Were Issued Under');

        $this->assertNotNull($credentialsRow);
        $this->assertNull($credentialsRow->getWarning());
    }


    /**
     * Clearing the identifier retires the identity and withdraws its document, which is exactly the
     * change a list created under it can not follow: it keeps signing under what it recorded.
     */
    public function testWarnsAboutStatusListIdentitiesOnceTheIdentifierIsCleared(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder(
                [
                    ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => VciIssuerIdentifierModeEnum::DidJwk,
                    ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => null,
                ],
                statusListIssuerIdentifiers: [self::DID_WEB_WITH_PATH],
            )->build(),
            'Identities Status Lists Are Signed Under',
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('not the configured did:web', (string)$row->getWarning());
    }


    /**
     * Lists which already exist keep being served whatever the switch says, so the obligation their
     * identifiers carry does not go away with it.
     */
    public function testReportsStatusListIdentitiesWhileStatusListsAreDisabled(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder(
                [
                    ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => false,
                    ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => null,
                ],
                statusListIssuerIdentifiers: ['did:web:retired.example.org'],
            )->build(),
            'Identities Status Lists Are Signed Under',
        );

        $this->assertNotNull($row);
        $this->assertSame(['did:web:retired.example.org'], $row->getValue());
        $this->assertNotNull($row->getWarning());
    }


    /**
     * These screens are what an administrator opens when the database is already unhappy, so a read
     * which fails has to leave the rest of the page standing.
     */
    public function testSurvivesAFailureToReadTheStatusListIdentities(): void
    {
        $sections = $this->buildVciOverviewBuilder(
            statusListIssuerIdentifiers: new RuntimeException('No such column: issuer_identifier'),
        )->build();

        $row = $this->findRowByLabel($sections, 'Identities Status Lists Are Signed Under');

        $this->assertNotNull($row);
        $this->assertSame('N/A', $row->getValue());
        $this->assertStringContainsString('could not be read', (string)$row->getWarning());
        $this->assertNotEmpty($sections);
    }


    /**
     * The identifiers come from storage and the configured did:web only decides whether to warn about
     * them, so a malformed option must not cost the reader the list itself -- that option is reported
     * on its own row, and this is the screen an administrator is on while fixing it.
     */
    public function testStillListsStatusListIdentitiesWhenTheConfiguredDidWebIsMalformed(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder(
                [ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => 'not-a-did'],
                statusListIssuerIdentifiers: [self::DID_WEB_WITH_PATH],
            )->build(),
            'Identities Status Lists Are Signed Under',
        );

        $this->assertNotNull($row);
        $this->assertSame([self::DID_WEB_WITH_PATH], $row->getValue());
        $this->assertStringContainsString('could not be read', (string)$row->getWarning());
    }


    /**
     * Clearing the identifier while the mode still names did:web is the one pairing the two options
     * can not be resolved into together -- and it is also precisely the state this row exists to
     * report, since clearing the option is what withdraws the document the lists still name. Asking
     * for the identifier alone, as the endpoint which publishes the document does, is what keeps the
     * warning from being reported as an unreadable configuration.
     */
    public function testWarnsAboutStatusListIdentitiesWhenTheModeStillNamesAClearedDidWeb(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder(
                [
                    ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => VciIssuerIdentifierModeEnum::DidWeb,
                    ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => null,
                ],
                statusListIssuerIdentifiers: [self::DID_WEB_WITH_PATH],
            )->build(),
            'Identities Status Lists Are Signed Under',
        );

        $this->assertNotNull($row);
        $this->assertStringContainsString('not the configured did:web', (string)$row->getWarning());
    }


    /**
     * A malformed mode says nothing about which document is published, so it must not cost this row
     * its comparison either.
     */
    public function testStillComparesStatusListIdentitiesWhenTheIssuerModeIsMalformed(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder(
                [
                    ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => 'not-a-mode',
                    ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => self::DID_WEB_WITH_PATH,
                ],
                statusListIssuerIdentifiers: [self::DID_WEB_WITH_PATH],
            )->build(),
            'Identities Status Lists Are Signed Under',
        );

        $this->assertNotNull($row);
        $this->assertNull($row->getWarning());
    }


    /**
     * The same coupling, in the row which answers for credentials. It predates this change and is the
     * identical defect: the state it has to report is the state the paired accessor refuses.
     */
    public function testWarnsAboutIssuedIdentitiesWhenTheModeStillNamesAClearedDidWeb(): void
    {
        $row = $this->findRowByLabel(
            $this->buildVciOverviewBuilder(
                [
                    ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => VciIssuerIdentifierModeEnum::DidWeb,
                    ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => null,
                ],
                ['did:web:retired.example.org' => VciIssuerIdentifierModeEnum::DidWeb->value],
            )->build(),
            'Identities Credentials Were Issued Under',
        );

        $this->assertNotNull($row);
        $this->assertSame(['did:web:retired.example.org'], $row->getValue());
        $this->assertStringContainsString('can no longer be verified', (string)$row->getWarning());
    }


    /**
     * A Status List pool with every knob set away from its default, so a value which reached the
     * screen from the wrong pool field shows up rather than being coincidentally right. The module
     * level key profile stays at its own default, which the pool then overrides.
     *
     * @return array<string,mixed>
     */
    protected static function statusListPoolOverrides(bool $areStatusListsEnabled = true): array
    {
        return [
            ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => $areStatusListsEnabled,
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => ['TestCredential' => []],
            ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS => [
                'default' => [
                    StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['TestCredential'],
                    StatusListPool::KEY_BITS => 2,
                    StatusListPool::KEY_CAPACITY => 1024,
                    StatusListPool::KEY_ALLOWED_STATUSES => [StatusTypeEnum::Suspended],
                    StatusListPool::KEY_TTL => 'PT6H',
                    StatusListPool::KEY_TOKEN_VALIDITY => 'P2D',
                    StatusListPool::KEY_REFRESH_INTERVAL => 'PT2H',
                    StatusListPool::KEY_KEY_PROFILE => StatusListKeyProfileEnum::Jwks->value,
                ],
            ],
        ];
    }


    /**
     * A redirect URI prefix which is not a string but does have a string form.
     */
    protected function stringablePrefix(string $value): Stringable
    {
        return new readonly class ($value) implements Stringable {
            public function __construct(protected string $value)
            {
            }


            public function __toString(): string
            {
                return $this->value;
            }
        };
    }


    /**
     * A redirect URI prefix whose string form can not be produced at all.
     */
    protected function throwingStringablePrefix(): Stringable
    {
        return new class implements Stringable {
            public function __toString(): string
            {
                throw new RuntimeException('This prefix has no string form.');
            }
        };
    }


    /**
     * Both notes have to be there, because the switch does less than its name suggests: turning it
     * off stops new credentials getting an entry, it does not stop lists already published being
     * served, so it can not be read as a way to make revocation go away.
     */
    public function testSaysWhatEnablingStatusListsDoes(): void
    {
        // Configured with a pool, so what the enabled note promises is a deployment which does
        // allocate entries. Without one nothing allocates, which the pools row says for itself.
        $enabledRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder(self::statusListPoolOverrides(true))->build(),
            ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED,
        );
        $this->assertNotNull($enabledRow);
        $this->assertSame('Yes', $enabledRow->getValue());
        $this->assertStringContainsString('can be revoked and suspended', (string)$enabledRow->getNote());

        $disabledRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder(self::statusListPoolOverrides(false))->build(),
            ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED,
        );
        $this->assertNotNull($disabledRow);
        $this->assertSame('No', $disabledRow->getValue());
        $this->assertStringContainsString('keep being served', (string)$disabledRow->getNote());
    }


    /**
     * Every field of a pool decides something an administrator can not see anywhere else: the bit
     * width fixes which statuses the lists can ever carry, the capacity fixes how many credentials
     * share one list and so how large the group each credential hides in is, and the key profile
     * decides how the tokens name their signing key. So the row is asserted field by field, against
     * a pool configured away from every default.
     */
    public function testDescribesEveryFieldOfAConfiguredStatusListPool(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder(self::statusListPoolOverrides())->build(),
            ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS,
        );

        $this->assertNotNull($row);
        $this->assertSame(ConfigOverviewValueTypeEnum::Json, $row->getValueType());
        $this->assertSame(
            [
                'default' => [
                    StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['TestCredential'],
                    StatusListPool::KEY_BITS => 2,
                    StatusListPool::KEY_CAPACITY => 1024,
                    // Valid is allowed whether or not it was configured, since a revoked entry has to
                    // be able to be reinstated.
                    StatusListPool::KEY_ALLOWED_STATUSES => ['Valid', 'Suspended'],
                    StatusListPool::KEY_TTL => 'PT6H',
                    StatusListPool::KEY_TOKEN_VALIDITY => 'P2D',
                    StatusListPool::KEY_REFRESH_INTERVAL => 'PT2H',
                    // The pool's own profile, not the module level default, which is did_jwk.
                    StatusListPool::KEY_KEY_PROFILE => StatusListKeyProfileEnum::Jwks->value,
                ],
            ],
            $row->getValue(),
        );
    }


    /**
     * Pools are readable while the capability is off, and they are then inert. Saying so matters:
     * the configuration looks complete, and nothing else on the screen would explain why no
     * credential being issued gets an entry.
     */
    public function testSaysConfiguredPoolsAreInertWhileStatusListsAreDisabled(): void
    {
        $enabledRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder(self::statusListPoolOverrides(true))->build(),
            ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS,
        );
        $this->assertNotNull($enabledRow);
        $this->assertStringContainsString('smaller group each credential hides in', (string)$enabledRow->getNote());

        $disabledRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder(self::statusListPoolOverrides(false))->build(),
            ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS,
        );
        $this->assertNotNull($disabledRow);
        // Still described in full, so what is configured stays visible: the switch changes the note,
        // and nothing else about the row.
        $this->assertSame($enabledRow->getValue(), $disabledRow->getValue());
        $this->assertStringContainsString('inert', (string)$disabledRow->getNote());
    }


    /**
     * With no pool configured nothing allocates, so no issued credential can be revoked. That is a
     * different statement from the capability being off, and the screen has to make it.
     */
    public function testSaysNoPoolIsConfigured(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => true])->build(),
            ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS,
        );

        $this->assertNotNull($row);
        $this->assertSame('None configured', $row->getValue());
        // The placeholder is UI text, where a configured pool is structured data.
        $this->assertSame(ConfigOverviewValueTypeEnum::Text, $row->getValueType());
        $this->assertStringContainsString(
            'No credential configuration allocates a Status List entry',
            (string)$row->getNote(),
        );
        $this->assertStringContainsString('no issued credential can be revoked', (string)$row->getNote());
    }


    /**
     * The limit is applied per address as the request appears to arrive, which behind a proxy is the
     * proxy. An administrator who does not know that configures one shared bucket for every client.
     */
    public function testSaysWhatARequestLimitIsAppliedTo(): void
    {
        $limitedRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE => 60,
            ])->build(),
            ModuleConfig::OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE,
        );
        $this->assertNotNull($limitedRow);
        $this->assertSame('60', $limitedRow->getValue());
        $this->assertSame(ConfigOverviewValueTypeEnum::RawText, $limitedRow->getValueType());
        $this->assertStringContainsString('reverse proxy', (string)$limitedRow->getNote());

        $unlimitedRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder()->build(),
            ModuleConfig::OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE,
        );
        $this->assertNotNull($unlimitedRow);
        $this->assertSame('No limit', $unlimitedRow->getValue());
        // The placeholder is UI text, the number is data.
        $this->assertSame(ConfigOverviewValueTypeEnum::Text, $unlimitedRow->getValueType());
        $this->assertStringContainsString('unauthenticated', (string)$unlimitedRow->getNote());
    }


    /**
     * The endpoint and the capability are separate switches, and the combination which does nothing
     * useful is the endpoint being served while nothing allocates entries any more.
     */
    public function testWarnsWhenTheCredentialStatusEndpointIsServedWhileStatusListsAreOff(): void
    {
        $withoutStatusLists = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                // VciCredentialStatusApiController refuses every request while the module API is off,
                // so the endpoint is only really served with both switches on.
                ModuleConfig::OPTION_API_ENABLED => true,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED => true,
                ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => false,
            ])->build(),
            ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED,
        );
        $this->assertNotNull($withoutStatusLists);
        $this->assertSame('Yes', $withoutStatusLists->getValue());
        // Which credential it authenticates as is the part an administrator has to know.
        $this->assertStringContainsString('bearer token', (string)$withoutStatusLists->getNote());
        $this->assertStringContainsString('no entry to change', (string)$withoutStatusLists->getWarning());

        $withStatusLists = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_API_ENABLED => true,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED => true,
                ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => true,
            ])->build(),
            ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED,
        );
        $this->assertNotNull($withStatusLists);
        $this->assertSame('Yes', $withStatusLists->getValue());
        $this->assertStringContainsString('bearer token', (string)$withStatusLists->getNote());
        $this->assertNull($withStatusLists->getWarning());

        $disabledEndpoint = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_API_ENABLED => true,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED => false,
                ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => false,
            ])->build(),
            ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED,
        );
        $this->assertNotNull($disabledEndpoint);
        $this->assertSame('No', $disabledEndpoint->getValue());
        $this->assertStringContainsString('administration screens', (string)$disabledEndpoint->getNote());
        // Nothing is served, so there is nothing to warn about.
        $this->assertNull($disabledEndpoint->getWarning());
    }


    /**
     * Pinned rather than endorsed, and queued as a production fix.
     *
     * The credential offer row warns when its endpoint is enabled while the module API is off. The
     * credential status row has no such warning, and the one warning it does have is decided by its
     * own switch alone. So with the API off it reports that credentials being issued have no entry
     * to change, about an endpoint VciCredentialStatusApiController refuses to serve at all, and
     * never mentions the switch which is actually stopping it.
     */
    public function testTheCredentialStatusRowDoesNotYetNoticeTheModuleApiIsOff(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_API_ENABLED => false,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED => true,
                ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => false,
            ])->build(),
            ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED,
        );

        $this->assertNotNull($row);
        // Warns about an endpoint which is not served at all.
        $this->assertStringContainsString('no entry to change', (string)$row->getWarning());
        // And says nothing about the switch which is the reason it is not served.
        $this->assertStringNotContainsString('module API', (string)$row->getWarning());
    }


    /**
     * The audit trail records who asked for which status change, so what it says about retention is
     * a privacy statement as much as a storage one.
     */
    public function testSaysHowLongTheStatusAuditTrailIsKept(): void
    {
        $configuredRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION => 'P90D',
            ])->build(),
            ModuleConfig::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION,
        );
        $this->assertNotNull($configuredRow);
        $this->assertSame('P90D', $configuredRow->getValue());
        $this->assertSame(ConfigOverviewValueTypeEnum::RawText, $configuredRow->getValueType());
        $this->assertStringContainsString('pruned', (string)$configuredRow->getNote());

        $indefiniteRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder()->build(),
            ModuleConfig::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION,
        );
        $this->assertNotNull($indefiniteRow);
        $this->assertSame('Kept indefinitely', $indefiniteRow->getValue());
        $this->assertSame(ConfigOverviewValueTypeEnum::Text, $indefiniteRow->getValueType());
        // Says what is actually retained, since keeping it for good is the default.
        $this->assertStringContainsString('kept for', (string)$indefiniteRow->getNote());
        $this->assertStringContainsString('actor', (string)$indefiniteRow->getNote());
    }


    /**
     * Every row which shows a URL has to carry its own. They are all built the same way from the one
     * Routes instance, so a row pointing at a neighbouring route would look entirely normal. Covers
     * the four endpoint rows and the two configuration URLs on the entity section.
     */
    public function testEachUrlRowPointsAtItsOwnRoute(): void
    {
        $urls = [
            'Credential' => 'https://op.example.org/credential',
            'Nonce' => 'https://op.example.org/nonce',
            'Credential Offer (API)' => 'https://op.example.org/api/credential-offer',
            'Credential Status (API)' => 'https://op.example.org/api/credential-status',
            'Credential Issuer Configuration URL' => 'https://op.example.org/credential-issuer-config',
            'JWT VC Issuer Configuration URL' => 'https://op.example.org/jwt-vc-issuer-config',
        ];

        $sections = $this->buildVciOverviewBuilder(
            [
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_API_ENABLED => true,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED => true,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED => true,
            ],
            routeUrls: [
                'urlCredentialIssuerCredential' => $urls['Credential'],
                'urlCredentialIssuerNonce' => $urls['Nonce'],
                'urlApiVciCredentialOffer' => $urls['Credential Offer (API)'],
                'urlApiVciCredentialStatus' => $urls['Credential Status (API)'],
                'urlCredentialIssuerConfiguration' => $urls['Credential Issuer Configuration URL'],
                'urlJwtVcIssuerConfiguration' => $urls['JWT VC Issuer Configuration URL'],
            ],
        )->build();

        foreach ($urls as $label => $url) {
            $row = $this->findRowByLabel($sections, $label);

            $this->assertNotNull($row, "Missing row for $label");
            $this->assertSame($url, $row->getValue(), "Row \"$label\" does not point at its own route");
            $this->assertSame(ConfigOverviewValueTypeEnum::Url, $row->getValueType());
        }
    }


    /**
     * The credential status endpoint needs the module API and its own switch, and deliberately not
     * the issuance switch: credentials already in wallets stay revocable while issuance is off, and
     * hiding the URL of a live endpoint during the incident which made someone turn issuance off is
     * exactly the wrong moment to do it.
     */
    public function testListsTheCredentialStatusApiEndpointOnlyWhenItIsServed(): void
    {
        $labels = fn(array $sections): array => array_map(
            fn($row): string => $row->getLabel(),
            $this->flattenRows($sections),
        );

        $this->assertNotContains(
            'Credential Status (API)',
            $labels($this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_API_ENABLED => true,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED => false,
            ])->build()),
        );

        $this->assertNotContains(
            'Credential Status (API)',
            $labels($this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_API_ENABLED => false,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED => true,
            ])->build()),
        );

        $this->assertContains(
            'Credential Status (API)',
            $labels($this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => false,
                ModuleConfig::OPTION_API_ENABLED => true,
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED => true,
            ])->build()),
            'The credential status endpoint is served while issuance is off, so it must stay listed',
        );
    }


    /**
     * A malformed api_enabled belongs to the protocol screen. Here the conservative reading is that
     * the endpoint is not served, rather than the section failing over an option it does not own.
     */
    public function testDoesNotListTheOfferEndpointWhenTheApiSwitchIsMalformed(): void
    {
        $labels = array_map(
            fn($row): string => $row->getLabel(),
            $this->flattenRows($this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_API_ENABLED => 'nope',
                ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED => true,
            ])->build()),
        );

        $this->assertNotContains('Credential Offer (API)', $labels);
        // The section itself still renders.
        $this->assertContains('Credential', $labels);
    }


    /**
     * Requiring a key proof is the default, so listing every configuration which does would bury the
     * ones which do something else, and it is those an administrator needs to recognise on sight.
     */
    public function testListsOnlyTheCredentialConfigurationsWhichDepartFromTheDefault(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'DefaultOne' => [],
                    'DiipOne' => [],
                ],
                ModuleConfig::OPTION_VCI_CREDENTIAL_BINDING_POLICIES => [
                    'DefaultOne' => VciCredentialBindingPolicyEnum::ProofBound->value,
                    'DiipOne' => VciCredentialBindingPolicyEnum::DiipProofBound->value,
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_BINDING_POLICIES,
        );

        $this->assertNotNull($row);
        $this->assertSame(ConfigOverviewValueTypeEnum::StringList, $row->getValueType());
        $this->assertSame(
            ['DiipOne: ' . VciCredentialBindingPolicyEnum::DiipProofBound->value],
            $row->getValue(),
        );
        $this->assertStringContainsString(
            VciCredentialBindingPolicyEnum::DiipProofBound->value,
            (string)$row->getNote(),
        );
        // Nothing here issues without a key proof.
        $this->assertNull($row->getWarning());
    }


    /**
     * With no exception configured the row says so rather than listing everything.
     */
    public function testSaysEveryCredentialConfigurationRequiresAKeyProof(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => ['DefaultOne' => []],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_BINDING_POLICIES,
        );

        $this->assertNotNull($row);
        $this->assertSame('Every configuration requires a key proof', $row->getValue());
        $this->assertSame(ConfigOverviewValueTypeEnum::Text, $row->getValueType());
        $this->assertStringContainsString('which is the default', (string)$row->getNote());
        $this->assertStringContainsString('no valid key proof is refused', (string)$row->getNote());
        $this->assertNull($row->getWarning());
    }


    /**
     * A proofless configuration issues credentials bound to no wallet key at all, so nothing ties an
     * issued credential to whoever presents it later. That is not a detail of a listing, it is a
     * warning.
     */
    public function testWarnsAboutCredentialConfigurationsWhichIssueWithoutAKeyProof(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'DefaultOne' => [],
                    'ProoflessOne' => [],
                ],
                // Proofless is the only exception, so the warning can only be attributable to it and
                // not to some other configuration merely departing from the default.
                ModuleConfig::OPTION_VCI_CREDENTIAL_BINDING_POLICIES => [
                    'ProoflessOne' => VciCredentialBindingPolicyEnum::Proofless->value,
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_BINDING_POLICIES,
        );

        $this->assertNotNull($row);
        $this->assertSame(
            ['ProoflessOne: ' . VciCredentialBindingPolicyEnum::Proofless->value],
            $row->getValue(),
        );
        $this->assertStringContainsString('not bound to any wallet key', (string)$row->getWarning());
    }


    /**
     * A configuration with no lifetime issues credentials which never expire, so listing only the
     * ones which have one is the whole content of this row.
     */
    public function testShowsTheLifetimeOfEachCredentialConfigurationWhichHasOne(): void
    {
        $configuredRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'ShortLived' => [],
                    'Forever' => [],
                ],
                ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS => ['ShortLived' => 'P30D'],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS,
        );

        $this->assertNotNull($configuredRow);
        $this->assertSame(ConfigOverviewValueTypeEnum::StringMap, $configuredRow->getValueType());
        $this->assertSame(['ShortLived' => ['P30D']], $configuredRow->getValue());
        $this->assertStringContainsString('not listed', (string)$configuredRow->getNote());

        $noneRow = $this->findRowForOption(
            $this->buildVciOverviewBuilder()->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS,
        );
        $this->assertNotNull($noneRow);
        $this->assertSame('None configured', $noneRow->getValue());
        $this->assertSame(ConfigOverviewValueTypeEnum::Text, $noneRow->getValueType());
        // Says what those lists cost, since they can never be retired.
        $this->assertStringContainsString('never expire', (string)$noneRow->getNote());
        $this->assertStringContainsString('never be retired', (string)$noneRow->getNote());
    }


    public function testNotesTheConfiguredNonceTtl(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([ModuleConfig::OPTION_VCI_NONCE_TTL => 'PT2M'])->build(),
            ModuleConfig::OPTION_VCI_NONCE_TTL,
        );

        $this->assertNotNull($row);
        $this->assertSame('2 minutes (PT2M)', $row->getValue());
        $this->assertStringContainsString('nonce stays valid', (string)$row->getNote());
        $this->assertStringNotContainsString('falls back', (string)$row->getNote());
    }


    /**
     * ClientRedirectUriRule casts with (string), which an object implementing Stringable survives.
     * The prefix it becomes is what the runtime will match on, so that is what is shown.
     */
    public function testShowsAStringableRedirectPrefixAsTheRuntimeCastsIt(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS => true,
                ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS => [
                    // Deliberately not 'openid-credential-offer://', which is what the option falls
                    // back to when it is not configured at all, and so proves nothing about the cast.
                    $this->stringablePrefix('custom-wallet-app://'),
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS,
        );

        $this->assertNotNull($row);
        $this->assertSame(['custom-wallet-app://'], $row->getValue());
        // It does match at runtime, but it is not what anyone means to configure.
        $this->assertStringContainsString('not a string', (string)$row->getWarning());
    }


    /**
     * A prefix with no string form at all is a different failure: at runtime the cast raises rather
     * than matching, so the check fails instead of letting anything through. Two shapes reach it,
     * an object which is not Stringable and one whose __toString() throws.
     */
    public function testWarnsAboutARedirectPrefixWhichCannotBeCastAtAll(): void
    {
        $prefixes = [
            'not stringable' => new stdClass(),
            'throws while being cast' => $this->throwingStringablePrefix(),
        ];

        foreach ($prefixes as $description => $prefix) {
            $row = $this->findRowForOption(
                $this->buildVciOverviewBuilder([
                    ModuleConfig::OPTION_VCI_ENABLED => true,
                    ModuleConfig::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS => true,
                    ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS => [$prefix],
                ])->build(),
                ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS,
            );

            $this->assertNotNull($row, "No row for a prefix which $description");
            // Nothing to show, since there is no prefix it becomes.
            $this->assertSame([], $row->getValue(), "A prefix which $description was shown as something");
            $this->assertStringContainsString(
                'cannot be turned into a string',
                (string)$row->getWarning(),
                "A prefix which $description was not warned about",
            );
        }
    }


    /**
     * The display block carries one entry per locale, and a malformed entry among them must cost
     * only its own name.
     */
    public function testSkipsDisplayEntriesWhichAreNotArrays(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'PartlyMalformed' => [
                        'format' => 'jwt_vc_json',
                        'credential_metadata' => [
                            'display' => [
                                'not-an-array',
                                ['name' => 'Readable Name', 'locale' => 'en-US'],
                                // No name at all, so it contributes none.
                                ['locale' => 'hr-HR'],
                            ],
                        ],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);
        $this->assertSame(['Readable Name'], $configurations[0]['displayNames']);
        // Dropped quietly: nothing about the surviving configuration is wrong.
        $this->assertNull($row->getWarning());
    }


    /**
     * ModuleConfig keeps any truthy 'path' a claim declares, including one written as a dotted
     * string. Issuance matches a mapping against these verbatim, so a path which is not an array
     * matches nothing and is not a claim path this configuration has.
     */
    public function testSkipsDeclaredClaimPathsWhichAreNotArrays(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'PartlyMalformed' => [
                        'format' => 'jwt_vc_json',
                        'credential_metadata' => [
                            'claims' => [
                                ['path' => 'written.as.a.string'],
                                ['path' => ['credentialSubject', 'mail']],
                            ],
                        ],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);
        $this->assertSame(['credentialSubject.mail'], $configurations[0]['claimPaths']);
        // Dropped quietly, as above.
        $this->assertNull($row->getWarning());
    }


    /**
     * The attribute map is a list of single pair entries. One which is not a pair at all is dropped
     * rather than taking the rest of the configuration's mappings with it.
     */
    public function testSkipsMappingEntriesWhichAreNotArrays(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => self::credentialConfiguration(),
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                    'ResearchAndScholarshipCredentialJwtVcJson' => [
                        'not-an-array',
                        ['mail' => ['credentialSubject', 'mail']],
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
        $this->assertTrue($mappings[0]['isEffective']);
        // The entry is dropped quietly: nothing about the surviving configuration is wrong.
        $this->assertNull($row->getWarning());
    }


    /**
     * Issuance requires the configured path to be an array before it looks for it among the declared
     * claim paths, so a path written as a dotted string is applied to nothing. It is shown as
     * configured, since that is what has to be corrected, and marked ineffective.
     */
    public function testMarksAMappingWhoseClaimPathIsNotAnArrayAsIneffective(): void
    {
        $row = $this->findRowForOption(
            $this->buildVciOverviewBuilder([
                ModuleConfig::OPTION_VCI_ENABLED => true,
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => self::credentialConfiguration(),
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP => [
                    'ResearchAndScholarshipCredentialJwtVcJson' => [
                        ['mail' => 'credentialSubject.mail'],
                    ],
                ],
            ])->build(),
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
        );

        $this->assertNotNull($row);

        $configurations = $row->getValue();
        $this->assertIsArray($configurations);

        $mapping = $configurations[0]['attributeMappings'][0];
        $this->assertSame('mail', $mapping['attribute']);
        $this->assertSame('credentialSubject.mail', $mapping['path']);
        $this->assertFalse($mapping['isEffective']);
        $this->assertSame('notDeclared', $mapping['ineffectiveReason']);

        $this->assertStringContainsString('never reaches the credential', (string)$row->getWarning());
    }
}

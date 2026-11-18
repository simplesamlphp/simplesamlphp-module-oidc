<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Entities\ClaimSetEntity;
use SimpleSAML\Module\oidc\Factories\ClaimTranslatorExtractorFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

#[CoversClass(ClaimTranslatorExtractorFactory::class)]
#[AllowMockObjectsWithoutExpectations]
class ClaimTranslatorExtractorFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $claimSetEntityFactory;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock
            ->method('config')
            ->willReturn(
                Configuration::loadFromArray(
                    [
                        ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE => 'uid',
                        ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE => [
                            'testClaim' => ['attribute'],
                            'intClaim' => [
                                'type' => 'int',
                                'intAttribute',
                            ],
                            'testClaim2' => ['attribute2'],
                            'boolClaim' => [
                                'type' => 'bool',
                                'attributes' => ['boolAttribute'],
                            ],
                        ],
                    ],
                ),
            );
        $this->moduleConfigMock
            ->method('getPrivateScopes')
            ->willReturn(
                [
                    'customScope1' => [
                        'claims' => ['testClaim', 'intClaim'],
                    ],
                    'customScope2' => [
                        'claims' => ['testClaim2', 'boolClaim'],
                        'claim_name_prefix' => 'myprefix_',
                    ],
                    'customScope3' => [
                        'claims' => ['testClaim3', 'boolClaim'],
                    ],
                ],
            );

        $this->claimSetEntityFactory = $this->createMock(ClaimSetEntityFactory::class);
    }


    protected function mock(): ClaimTranslatorExtractorFactory
    {
        return new ClaimTranslatorExtractorFactory(
            $this->moduleConfigMock,
            $this->claimSetEntityFactory,
        );
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(
            ClaimTranslatorExtractorFactory::class,
            $this->mock(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testCanBuildClaimTranslatorExtractor(): void
    {
        $this->assertInstanceOf(
            ClaimTranslatorExtractor::class,
            $this->mock()->build(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testExtractor(): void
    {
        $this->claimSetEntityFactory->expects($this->atLeastOnce())
            ->method('build')
            ->willReturnCallback(
                function (string $scope, array $claims): Stub {
                    $claimSetStub = $this->createStub(ClaimSetEntity::class);
                    $claimSetStub->method('getScope')->willReturn($scope);
                    $claimSetStub->method('getClaims')->willReturn($claims);
                    return $claimSetStub;
                },
            );

        $claimTranslatorExtractor = $this->mock()->build();

        $this->assertSame(
            $claimTranslatorExtractor->getClaimSet('customScope2')->getClaims(),
            ['myprefix_testClaim2', 'myprefix_boolClaim'],
        );

        $claimData = $claimTranslatorExtractor->extract(
            ['openid', 'email', 'profile', 'customScope1', 'customScope2'],
            [
                'cn' => ['Firsty Lasty'],
                'attribute' => ['val1'],
                'intAttribute' => ['56789'],
                'boolAttribute' => ['yes'],
                'attribute2' => ['val2'],
            ],
        );

        $this->assertSame(
            $claimData,
            [
                'name' => "Firsty Lasty",
                'testClaim' => "val1",
                'intClaim' => 56789,
                'myprefix_testClaim2' => "val2",
                'myprefix_boolClaim' => true,
            ],
        );
    }


    /**
     * A module configuration for the identity / access token claim tests: a fresh mock, so a test can set the
     * private scopes without fighting the ones setUp() configured, and real claim sets, so extraction works.
     */
    protected function moduleConfig(
        array $identityClaims = [],
        array $accessTokenClaims = [],
        array $privateScopes = [],
        array $translationTable = [],
    ): MockObject {
        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('config')->willReturn(Configuration::loadFromArray([
            ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE => 'uid',
            ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE => $translationTable,
        ]));
        $moduleConfig->method('getUserIdentifierAttributes')->willReturn(['uid']);
        $moduleConfig->method('getPrivateScopes')->willReturn($privateScopes);
        $moduleConfig->method('getIdentityClaims')->willReturn($identityClaims);
        $moduleConfig->method('getAccessTokenClaims')->willReturn($accessTokenClaims);

        return $moduleConfig;
    }


    protected function factory(MockObject $moduleConfig): ClaimTranslatorExtractorFactory
    {
        $this->claimSetEntityFactory->method('build')->willReturnCallback(
            fn(string $scope, array $claims): ClaimSetEntity => new ClaimSetEntity($scope, $claims),
        );

        return new ClaimTranslatorExtractorFactory($moduleConfig, $this->claimSetEntityFactory);
    }


    /**
     * The identity claims join the 'openid' claim set next to 'sub', so the scope which releases the subject
     * releases them too, and a scope which does not carry them does not.
     *
     * @throws \Exception
     */
    public function testAnIdentityClaimJoinsTheOpenIdClaimSet(): void
    {
        $extractor = $this->factory($this->moduleConfig(
            identityClaims: ['voperson_id'],
            translationTable: ['voperson_id' => ['voPersonID']],
        ))->build();

        $this->assertSame(['sub', 'voperson_id'], $extractor->getClaimSet('openid')?->getClaims());
        $this->assertSame(
            ['sub' => 'u1', 'voperson_id' => 'v1@example.org'],
            $extractor->extract(['openid'], ['uid' => ['u1'], 'voPersonID' => ['v1@example.org']]),
        );
        $this->assertArrayNotHasKey(
            'voperson_id',
            $extractor->extract(['profile'], ['uid' => ['u1'], 'voPersonID' => ['v1@example.org']]),
        );
    }


    /**
     * The names are matched against the effective table, which is the module defaults with the configured
     * table merged over them: a standard claim needs no entry of its own.
     *
     * @throws \Exception
     */
    public function testAcceptsClaimsFromTheDefaultTranslationTable(): void
    {
        $extractor = $this->factory($this->moduleConfig(
            identityClaims: ['email'],
            accessTokenClaims: ['name'],
        ))->build();

        $this->assertSame(
            ['sub' => 'u1', 'email' => 'u1@example.org'],
            $extractor->extract(['openid'], ['uid' => ['u1'], 'mail' => ['u1@example.org']]),
        );
    }


    /**
     * A claim with no translation would never be released, and silently so; refused with the option named.
     * The unprefixed name of a claim a private scope renames is the same fault seen from the effective
     * table (ModuleConfig refuses it earlier for the identity claims, from the raw options), as is a default
     * mapping the configuration emptied.
     *
     * @throws \Exception
     */
    #[DataProvider('untranslatedClaimProvider')]
    public function testRefusesAClaimWithNoTranslation(string $option, string $claimName): void
    {
        $factory = $this->factory($this->moduleConfig(
            identityClaims: $option === ModuleConfig::OPTION_AUTH_IDENTITY_CLAIMS ? [$claimName] : [],
            accessTokenClaims: $option === ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_CLAIMS ? [$claimName] : [],
            privateScopes: [
                'aarc' => ['claims' => ['eduperson_assurance'], 'claim_name_prefix' => 'aarc_'],
            ],
            translationTable: [
                'eduperson_assurance' => ['eduPersonAssurance'],
                'family_name' => [],
                'typed_but_empty' => ['type' => 'string', 'attributes' => []],
                'json_but_empty' => ['type' => 'json', 'claims' => []],
                'json_hollow' => ['type' => 'json', 'claims' => ['level' => []]],
            ],
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(
            sprintf('Invalid value in %s. Claim "%s" has no attribute translation', $option, $claimName),
        );

        $factory->build();
    }


    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public static function untranslatedClaimProvider(): array
    {
        $cases = [];

        foreach (
            [
                ModuleConfig::OPTION_AUTH_IDENTITY_CLAIMS,
                ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_CLAIMS,
            ] as $option
        ) {
            $cases[$option . ': a name the table does not have'] = [$option, 'unknown_claim'];
            $cases[$option . ': the unprefixed name of a claim a scope renames'] = [$option, 'eduperson_assurance'];
            $cases[$option . ': a default mapping the configuration emptied'] = [$option, 'family_name'];
            $cases[$option . ': a default mapping which is empty out of the box'] = [$option, 'middle_name'];
            $cases[$option . ': a mapping with a type but no attributes'] = [$option, 'typed_but_empty'];
            $cases[$option . ': a json mapping with no sub-claims'] = [$option, 'json_but_empty'];
            $cases[$option . ': a json mapping whose sub-claims translate nothing'] = [$option, 'json_hollow'];
        }

        return $cases;
    }


    /**
     * The prefixed name is what the effective table has, so that is the name to list.
     *
     * @throws \Exception
     */
    public function testAcceptsThePrefixedNameOfAClaimAScopeRenames(): void
    {
        $extractor = $this->factory($this->moduleConfig(
            identityClaims: ['aarc_voperson_id'],
            accessTokenClaims: ['aarc_eduperson_assurance'],
            privateScopes: [
                'aarc' => ['claims' => ['voperson_id', 'eduperson_assurance'], 'claim_name_prefix' => 'aarc_'],
            ],
            translationTable: [
                'voperson_id' => ['voPersonID'],
                'eduperson_assurance' => ['eduPersonAssurance'],
            ],
        ))->build();

        $this->assertSame(
            ['sub' => 'u1', 'aarc_voperson_id' => 'v1'],
            $extractor->extract(['openid'], ['uid' => ['u1'], 'voPersonID' => ['v1']]),
        );
    }


    /**
     * An identity claim is 'sub'-like, a single value in every location, and the extractor keeps it one whatever
     * its entry says; so an entry which asks for a list is refused rather than ignored. The same entry is a list
     * for a claim which is not an identity claim, and `false` is accepted for one which is.
     *
     * @throws \Exception
     */
    public function testRefusesAnIdentityClaimWhoseEntryAsksForAList(): void
    {
        $translationTable = [
            'voperson_id' => [
                ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true,
                'attributes' => ['voPersonID'],
            ],
        ];

        $this->assertSame(
            ['voperson_id' => ['v1', 'v2']],
            $this->factory($this->moduleConfig(
                privateScopes: ['bundle' => ['claims' => ['voperson_id']]],
                translationTable: $translationTable,
            ))->build()->extract(['bundle'], ['uid' => ['u1'], 'voPersonID' => ['v1', 'v2']]),
        );

        $this->factory($this->moduleConfig(
            identityClaims: ['voperson_id'],
            translationTable: [
                'voperson_id' => [
                    ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => false,
                    'attributes' => ['voPersonID'],
                ],
            ],
        ))->build();

        $factory = $this->factory($this->moduleConfig(
            identityClaims: ['voperson_id'],
            translationTable: $translationTable,
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(sprintf(
            'Invalid value in %s. Claim "voperson_id" sets "multi_valued" to true in the "%s" table, but an ' .
            'identity claim is a single value.',
            ModuleConfig::OPTION_AUTH_IDENTITY_CLAIMS,
            ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE,
        ));

        $factory->build();
    }


    /**
     * A multi-value setting is refused where it can not be honoured, by build() and by the effective table the
     * configuration overview shows.
     *
     * @throws \Exception
     */
    #[DataProvider('unhonourableMultiValuedSettingProvider')]
    public function testRefusesAMultiValuedSettingWhichCanNotBeHonoured(array $translationTable, string $message): void
    {
        $factory = $this->factory($this->moduleConfig(translationTable: $translationTable));

        try {
            $factory->effectiveTranslationTable();
            $this->fail('The effective table was given with the setting in it.');
        } catch (ConfigurationError $error) {
            $this->assertStringContainsString($message, $error->getMessage());
        }

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage($message);

        $factory->build();
    }


    /**
     * @return array<string, array{0: array, 1: string}>
     */
    public static function unhonourableMultiValuedSettingProvider(): array
    {
        $key = ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED;
        $prefix = 'Invalid value in ' . ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE . '. ';
        $notABoolean = '; it takes true (the claim is a list) or false (a single value).';
        $json = ' to true, but it is translated to type \'json\', which yields a JSON object, not a list.';
        $standard = ' an OpenID Connect standard claim (OpenID Connect Core 1.0 section 5.1), which is a single ' .
        'value.';

        return [
            'a string' => [
                ['eduperson_affiliation' => [$key => 'yes', 'attributes' => ['eduPersonAffiliation']]],
                $prefix . 'Claim "eduperson_affiliation" sets "multi_valued" to a value of type string' . $notABoolean,
            ],
            'an integer, attributes listed directly' => [
                ['eduperson_affiliation' => [$key => 1, 'eduPersonAffiliation']],
                $prefix . 'Claim "eduperson_affiliation" sets "multi_valued" to a value of type int' . $notABoolean,
            ],
            'null' => [
                ['eduperson_affiliation' => [$key => null, 'attributes' => ['eduPersonAffiliation']]],
                $prefix . 'Claim "eduperson_affiliation" sets "multi_valued" to a value of type null' . $notABoolean,
            ],
            'not a boolean, on a member' => [
                ['affiliation' => ['type' => 'json', 'claims' => ['all' => [$key => 'no', 'attributes' => ['a']]]]],
                $prefix . 'Claim "affiliation.all" sets "multi_valued" to a value of type string' . $notABoolean,
            ],
            'true on a json claim' => [
                ['affiliation' => ['type' => 'json', $key => true, 'claims' => ['all' => ['eduPersonAffiliation']]]],
                $prefix . 'Claim "affiliation" sets "multi_valued"' . $json,
            ],
            'true on a json member' => [
                [
                    'outer' => [
                        'type' => 'json',
                        'claims' => ['inner' => ['type' => 'json', $key => true, 'claims' => ['leaf' => ['a']]]],
                    ],
                ],
                $prefix . 'Claim "outer.inner" sets "multi_valued"' . $json,
            ],
            'true on a standard claim' => [
                ['email' => [$key => true, 'attributes' => ['mail']]],
                $prefix . 'Claim "email" sets "multi_valued" to true, but it is' . $standard,
            ],
            'true on sub' => [
                ['sub' => [$key => true, 'uid']],
                $prefix . 'Claim "sub" sets "multi_valued" to true, but it is' . $standard,
            ],
            'true on a member of a standard claim' => [
                ['address' => ['type' => 'json', 'claims' => ['formatted' => [$key => true, 'postalAddress']]]],
                $prefix . 'Claim "address.formatted" sets "multi_valued" to true, but it is part of "address",' .
                $standard,
            ],
        ];
    }


    /**
     * False is accepted anywhere, and true where it can be honoured. A standard claim's name is a standard claim
     * only at the top of the effective table: a member named like one is not, and neither is a claim which a
     * private scope renames, whose setting follows it to the prefixed name.
     *
     * @throws \Exception
     */
    public function testAcceptsAMultiValuedSettingWhichCanBeHonoured(): void
    {
        $key = ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED;
        $extractor = $this->factory($this->moduleConfig(
            privateScopes: [
                'contact' => ['claims' => ['contacts']],
                'aarc' => ['claims' => ['eduperson_assurance', 'nickname'], 'claim_name_prefix' => 'aarc_'],
            ],
            translationTable: [
                'email' => [$key => false, 'attributes' => ['mail']],
                'contacts' => ['type' => 'json', 'claims' => ['email' => [$key => true, 'attributes' => ['mail']]]],
                'eduperson_assurance' => [$key => true, 'attributes' => ['eduPersonAssurance']],
                'nickname' => [$key => true, 'attributes' => ['nick']],
            ],
        ))->build();
        $attributes = ['uid' => ['u1'], 'mail' => ['m1', 'm2'], 'eduPersonAssurance' => ['a1'], 'nick' => ['n1', 'n2']];

        $this->assertSame(['email' => 'm1'], $extractor->extract(['email'], $attributes));
        $this->assertSame(['contacts' => ['email' => ['m1', 'm2']]], $extractor->extract(['contact'], $attributes));

        $aarc = $extractor->extract(['aarc'], $attributes);
        $this->assertSame(['a1'], $aarc['aarc_eduperson_assurance'] ?? null);
        $this->assertSame(['n1', 'n2'], $aarc['aarc_nickname'] ?? null);
    }


    /**
     * The configuration overview reports a fault in the table's multi-value settings on the table's row, and
     * each claim option on its own: their checks do not read the settings of the table's other claims.
     *
     * @throws \Exception
     */
    public function testAMultiValuedFaultFailsTheTableAndNotTheClaimOptionChecks(): void
    {
        $factory = $this->factory($this->moduleConfig(
            identityClaims: ['voperson_id'],
            accessTokenClaims: ['voperson_id'],
            translationTable: [
                'voperson_id' => ['voPersonID'],
                'eduperson_affiliation' => [
                    ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => 'yes',
                    'attributes' => ['eduPersonAffiliation'],
                ],
            ],
        ));

        $factory->checkIdentityClaims();
        $factory->checkAccessTokenClaims();

        $this->expectException(ConfigurationError::class);
        $factory->effectiveTranslationTable();
    }


    /**
     * An identity claim stands next to 'sub', so its translation must yield a string; a 'json', 'int' or
     * 'bool' mapping is refused. The access token claims have no such rule.
     *
     * @throws \Exception
     */
    #[DataProvider('nonStringTranslationProvider')]
    public function testRefusesAnIdentityClaimWhichIsNotTranslatedToAString(string $claimName, array $mapping): void
    {
        $translationTable = [$claimName => $mapping];

        // Fine as an access token claim.
        $this->factory($this->moduleConfig(accessTokenClaims: [$claimName], translationTable: $translationTable))
            ->build();

        $factory = $this->factory($this->moduleConfig(
            identityClaims: [$claimName],
            translationTable: $translationTable,
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(sprintf(
            'Invalid value in %s. Claim "%s" is translated to type',
            ModuleConfig::OPTION_AUTH_IDENTITY_CLAIMS,
            $claimName,
        ));

        $factory->build();
    }


    /**
     * @return array<string, array{0: string, 1: array}>
     */
    public static function nonStringTranslationProvider(): array
    {
        return [
            'json' => ['assurance', ['type' => 'json', 'claims' => ['level' => ['eduPersonAssurance']]]],
            'int' => ['employee_number', ['type' => 'int', 'attributes' => ['employeeNumber']]],
            'bool' => ['verified', ['type' => 'bool', 'verifiedAttribute']],
        ];
    }


    /**
     * RFC 9068 section 2.2.3.1 has "groups", "roles" and "entitlements" carry lists, and the library refuses to
     * mint an access token with one of them carrying anything else; so an access token claim of one of these
     * names is accepted only when its translation yields a list, that is, when its entry sets "multi_valued" to
     * true.
     *
     * @throws \Exception
     */
    #[DataProvider('accessTokenListClaimProvider')]
    public function testAcceptsAnAccessTokenListClaimTranslatedToAList(string $claimName): void
    {
        $extractor = $this->factory($this->moduleConfig(
            accessTokenClaims: [$claimName],
            privateScopes: ['authz' => ['claims' => [$claimName]]],
            translationTable: [
                $claimName => [ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true, 'isMemberOf'],
            ],
        ))->build();

        $this->assertSame(
            [$claimName => ['g1', 'g2']],
            $extractor->extract(['authz'], ['uid' => ['u1'], 'isMemberOf' => ['g1', 'g2']]),
        );
    }


    /**
     * @throws \Exception
     */
    #[DataProvider('accessTokenListClaimTranslatedToASingleValueProvider')]
    public function testRefusesAnAccessTokenListClaimTranslatedToASingleValue(string $claimName, array $mapping): void
    {
        $factory = $this->factory($this->moduleConfig(
            accessTokenClaims: [$claimName],
            privateScopes: ['authz' => ['claims' => [$claimName]]],
            translationTable: [$claimName => $mapping],
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(sprintf(
            'Invalid value in %s. Claim "%s" is a list in a JWT access token (RFC 9068 section 2.2.3.1), but ' .
            'its translation yields a single value -- set "multi_valued" to true on its entry in the "%s" table.',
            ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_CLAIMS,
            $claimName,
            ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE,
        ));

        $factory->build();
    }


    /**
     * @return array<string, array{0: string, 1: array}>
     */
    public static function accessTokenListClaimTranslatedToASingleValueProvider(): array
    {
        $cases = [];

        foreach (self::accessTokenListClaimProvider() as $label => [$claimName]) {
            $cases[$label . ', no setting'] = [$claimName, ['isMemberOf']];
            $cases[$label . ', set to false'] = [
                $claimName,
                [ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => false, 'attributes' => ['isMemberOf']],
            ];
        }

        return $cases;
    }


    /**
     * A 'json' translation yields an object.
     *
     * @throws \Exception
     */
    public function testRefusesAnAccessTokenListClaimTranslatedToAJsonObject(): void
    {
        $factory = $this->factory($this->moduleConfig(
            accessTokenClaims: ['groups'],
            privateScopes: ['authz' => ['claims' => ['groups']]],
            translationTable: ['groups' => ['type' => 'json', 'claims' => ['names' => ['isMemberOf']]]],
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(sprintf(
            'Invalid value in %s. Claim "groups" is a list in a JWT access token (RFC 9068 section 2.2.3.1), but ' .
            'it is translated to type \'json\'',
            ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_CLAIMS,
        ));

        $factory->build();
    }


    /**
     * An identity claim is a single value, so it can never be one of the list claims.
     *
     * @throws \Exception
     */
    #[DataProvider('accessTokenListClaimProvider')]
    public function testRefusesAnIdentityClaimNamedLikeAnAccessTokenListClaim(string $claimName): void
    {
        $factory = $this->factory($this->moduleConfig(
            identityClaims: [$claimName],
            privateScopes: ['authz' => ['claims' => [$claimName]]],
            translationTable: [$claimName => ['isMemberOf']],
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(sprintf(
            'Invalid value in %s. Claim "%s" is a list in a JWT access token (RFC 9068 section 2.2.3.1), and ' .
            'an identity claim is a single value.',
            ModuleConfig::OPTION_AUTH_IDENTITY_CLAIMS,
            $claimName,
        ));

        $factory->build();
    }


    /**
     * @return array<string, array{0: string}>
     */
    public static function accessTokenListClaimProvider(): array
    {
        return [
            'groups' => ['groups'],
            'roles' => ['roles'],
            'entitlements' => ['entitlements'],
        ];
    }


    /**
     * The configuration overview reports each option on its own row, so it needs each check on its own: a
     * fault in one option must not fail the check of the other, nor the effective table (found by review).
     * build() runs both.
     *
     * @throws \Exception
     */
    public function testChecksEachClaimOptionOnItsOwn(): void
    {
        $translationTable = ['voperson_id' => ['voPersonID']];

        $badIdentityClaims = $this->factory($this->moduleConfig(
            identityClaims: ['unknown_claim'],
            accessTokenClaims: ['voperson_id'],
            translationTable: $translationTable,
        ));
        $badIdentityClaims->checkAccessTokenClaims();
        $this->assertArrayHasKey('voperson_id', $badIdentityClaims->effectiveTranslationTable());
        try {
            $badIdentityClaims->checkIdentityClaims();
            $this->fail('The identity claims check should have refused unknown_claim.');
        } catch (ConfigurationError $error) {
            $this->assertStringContainsString(ModuleConfig::OPTION_AUTH_IDENTITY_CLAIMS, $error->getMessage());
        }

        $badAccessTokenClaims = $this->factory($this->moduleConfig(
            identityClaims: ['voperson_id'],
            accessTokenClaims: ['unknown_claim'],
            translationTable: $translationTable,
        ));
        $badAccessTokenClaims->checkIdentityClaims();
        $this->assertArrayHasKey('voperson_id', $badAccessTokenClaims->effectiveTranslationTable());
        try {
            $badAccessTokenClaims->checkAccessTokenClaims();
            $this->fail('The access token claims check should have refused unknown_claim.');
        } catch (ConfigurationError $error) {
            $this->assertStringContainsString(ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_CLAIMS, $error->getMessage());
        }

        $this->expectException(ConfigurationError::class);
        $badAccessTokenClaims->build();
    }


    /**
     * A raw fault in the identity claims option surfaces from ModuleConfig::getIdentityClaims(); the access token
     * check and the effective table do not read that option, so they still answer.
     *
     * @throws \Exception
     */
    public function testARawIdentityClaimsFaultDoesNotStopTheOtherChecks(): void
    {
        $moduleConfig = $this->moduleConfig(
            accessTokenClaims: ['voperson_id'],
            translationTable: ['voperson_id' => ['voPersonID']],
        );
        $moduleConfig->method('getIdentityClaims')
            ->willThrowException(new ConfigurationError('Invalid value in identity_claims.'));
        $factory = $this->factory($moduleConfig);

        $factory->checkAccessTokenClaims();
        $this->assertArrayHasKey('voperson_id', $factory->effectiveTranslationTable());

        $this->expectException(ConfigurationError::class);
        $factory->checkIdentityClaims();
    }
}

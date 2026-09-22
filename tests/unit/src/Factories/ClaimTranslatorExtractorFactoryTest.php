<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
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

/**
 * @covers \SimpleSAML\Module\oidc\Factories\ClaimTranslatorExtractorFactory
 */
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
                        'are_multiple_claim_values_allowed' => true,
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
     * Translation happens before the scope filtering, so a multi-value flag on a scope which also carries an
     * identity claim would turn it into an array in every location, whether or not that scope is granted.
     * An identity claim is 'sub'-like and stays a single string; the same claim released through the
     * multi-value scope is single-valued too, and the scope's other claims keep their multiple values.
     *
     * @throws \Exception
     */
    public function testAnIdentityClaimIsSingleValuedWhateverAScopesMultiValueSetting(): void
    {
        $privateScopes = [
            'bundle' => [
                'claims' => ['voperson_id', 'eduperson_entitlement'],
                'are_multiple_claim_values_allowed' => true,
            ],
        ];
        $translationTable = [
            'voperson_id' => ['voPersonID'],
            'eduperson_entitlement' => ['eduPersonEntitlement'],
        ];
        $attributes = [
            'uid' => ['u1'],
            'voPersonID' => ['v1', 'v2'],
            'eduPersonEntitlement' => ['e1', 'e2'],
        ];

        // Without the identity claim the scope's setting applies, which is what makes the case below a check.
        $this->assertSame(
            ['voperson_id' => ['v1', 'v2'], 'eduperson_entitlement' => ['e1', 'e2']],
            $this->factory($this->moduleConfig(privateScopes: $privateScopes, translationTable: $translationTable))
                ->build()
                ->extract(['bundle'], $attributes),
        );

        $extractor = $this->factory($this->moduleConfig(
            identityClaims: ['voperson_id'],
            privateScopes: $privateScopes,
            translationTable: $translationTable,
        ))->build();

        $this->assertSame(
            ['sub' => 'u1', 'voperson_id' => 'v1'],
            $extractor->extract(['openid'], $attributes),
        );
        $this->assertSame(
            ['voperson_id' => 'v1', 'eduperson_entitlement' => ['e1', 'e2']],
            $extractor->extract(['bundle'], $attributes),
        );
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
     * names is accepted only when its translation yields a list, that is, when a private scope allows it
     * multiple values.
     *
     * @throws \Exception
     */
    #[DataProvider('accessTokenListClaimProvider')]
    public function testAcceptsAnAccessTokenListClaimWhichAScopeAllowsMultipleValues(string $claimName): void
    {
        $extractor = $this->factory($this->moduleConfig(
            accessTokenClaims: [$claimName],
            privateScopes: [
                'authz' => ['claims' => [$claimName], 'are_multiple_claim_values_allowed' => true],
            ],
            translationTable: [$claimName => ['isMemberOf']],
        ))->build();

        $this->assertSame(
            [$claimName => ['g1', 'g2']],
            $extractor->extract(['authz'], ['uid' => ['u1'], 'isMemberOf' => ['g1', 'g2']]),
        );
    }


    /**
     * @throws \Exception
     */
    #[DataProvider('accessTokenListClaimProvider')]
    public function testRefusesAnAccessTokenListClaimTranslatedToASingleValue(string $claimName): void
    {
        $factory = $this->factory($this->moduleConfig(
            accessTokenClaims: [$claimName],
            privateScopes: ['authz' => ['claims' => [$claimName]]],
            translationTable: [$claimName => ['isMemberOf']],
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(sprintf(
            'Invalid value in %s. Claim "%s" is a list in a JWT access token (RFC 9068 section 2.2.3.1), but ' .
            'its translation yields a single value',
            ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_CLAIMS,
            $claimName,
        ));

        $factory->build();
    }


    /**
     * A 'json' translation yields an object, whatever the multi-value setting of the scope.
     *
     * @throws \Exception
     */
    public function testRefusesAnAccessTokenListClaimTranslatedToAJsonObject(): void
    {
        $factory = $this->factory($this->moduleConfig(
            accessTokenClaims: ['groups'],
            privateScopes: ['authz' => ['claims' => ['groups'], 'are_multiple_claim_values_allowed' => true]],
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
     * An identity claim is single-valued whatever any scope says, so it can never be one of the list claims.
     *
     * @throws \Exception
     */
    #[DataProvider('accessTokenListClaimProvider')]
    public function testRefusesAnIdentityClaimNamedLikeAnAccessTokenListClaim(string $claimName): void
    {
        $factory = $this->factory($this->moduleConfig(
            identityClaims: [$claimName],
            privateScopes: [
                'authz' => ['claims' => [$claimName], 'are_multiple_claim_values_allowed' => true],
            ],
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

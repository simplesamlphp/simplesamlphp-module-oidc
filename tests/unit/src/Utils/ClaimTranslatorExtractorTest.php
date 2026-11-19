<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\ClaimSetEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Utils\Attributes;
use stdClass;

#[CoversClass(ClaimTranslatorExtractor::class)]
#[AllowMockObjectsWithoutExpectations]
class ClaimTranslatorExtractorTest extends TestCase
{
    /** @var string[] */
    protected static array $userIdAttrs = ['uid'];

    protected Stub $claimSetEntityFactoryStub;


    protected function setUp(): void
    {
        $this->claimSetEntityFactoryStub = $this->createStub(ClaimSetEntityFactory::class);
        $this->claimSetEntityFactoryStub->method('build')
            ->willReturnCallback(
                function (string $scope, array $claims): Stub {
                    $claimSetEntityStub = $this->createStub(ClaimSetEntity::class);
                    $claimSetEntityStub->method('getScope')->willReturn($scope);
                    $claimSetEntityStub->method('getClaims')->willReturn($claims);
                    return $claimSetEntityStub;
                },
            );
    }


    protected function mock(
        array $claimSets = [],
        array $translationTable = [],
        array $identityClaims = [],
    ): ClaimTranslatorExtractor {
        return new ClaimTranslatorExtractor(
            self::$userIdAttrs,
            $this->claimSetEntityFactoryStub,
            $claimSets,
            $translationTable,
            $identityClaims,
        );
    }


    /**
     * Test various type conversions work, including types in subobjects
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testTypeConversion(): void
    {
        $claimSet = new ClaimSetEntity(
            'typeConversion',
            [
                'intClaim',
                'boolClaim1',
                'boolClaimYes',
                'boolClaimTrue',
                'boolClaimOther',
                'defaultClaim',
                'stringClaim',
                'jsonClaim',
                // Test oid style claim names is not interpreted as a type of 'urn'
                'urn:oid:2.5.4.3',
            ],
        );
        $translate = [
            'intClaim' => [
                'type' => 'int',
                'attributes' => ['intAttribute'],
            ],
            'boolClaim1' => [
                'type' => 'bool',
                'attributes' => ['boolAttribute1'],
            ],
            'boolClaimYes' => [
                'type' => 'bool',
                'attributes' => ['boolAttributeYes'],
            ]
            ,
            'boolClaimTrue' => [
                'type' => 'bool',
                'attributes' => ['boolAttributeTrue'],
            ],
            'boolClaimOther' => [
                'type' => 'bool',
                'attributes' => ['boolAttributeOther'],
            ],
            'defaultClaim' => ['stringAttribute'],
            'stringClaim' => ['type' => 'string', 'attributes' => ['stringAttribute']],
            'jsonClaim' => [
                'type' => 'json',
                'claims' => [
                    'subIntClaim' => [
                        'type' => 'int',
                        'attributes' => ['intAttribute'],
                    ],
                    'subBoolClaim' => [
                        'type' => 'bool',
                        'attributes' => ['boolAttribute1'],
                    ],
                    'subStringClaim' => ['stringAttribute'],
                ],
            ],
            'urn:oid:2.5.4.3' => ['stringAttribute'],
        ];
        $userAttributes = (new Attributes())->normalizeAttributesArray(
            [
                'intAttribute' => '7890',
                'boolAttribute1' => '1',
                'boolAttributeYes' => 'yes',
                'boolAttributeTrue' => 'true',
                'boolAttributeOther' => 'anythingElseIsFalse',
                'stringAttribute' => 'someString',
            ],
        );
        $claimTranslator = $this->mock([$claimSet], $translate);
        $releasedClaims = $claimTranslator->extract(
            ['typeConversion'],
            $userAttributes,
        );
        $expectedClaims = [
            'intClaim' => 7890,
            'boolClaim1' => true,
            'boolClaimYes' => true,
            'boolClaimTrue' => true,
            'boolClaimOther' => false,
            'defaultClaim' => 'someString',
            'stringClaim' => 'someString',
            'jsonClaim' => [
                'subIntClaim' => 7890,
                'subBoolClaim' => true,
                'subStringClaim' => 'someString',
            ],
            'urn:oid:2.5.4.3' => 'someString',
        ];

        $this->assertSame($expectedClaims, $releasedClaims);
    }


    /**
     * Test that the default translator configuration sets address correctly.
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testDefaultTypeConversion(): void
    {
        // Address is the only non-string attribute with a default saml source
        $userAttributes = (new Attributes())->normalizeAttributesArray(
            [
                'postalAddress' => 'myAddress',
            ],
        );
        $claimTranslator = $this->mock();
        $releasedClaims = $claimTranslator->extract(
            ['address'],
            $userAttributes,
        );
        $expectedClaims = [
            'address' => [
                'formatted' => 'myAddress',
            ],
        ];

        $this->assertSame($expectedClaims, $releasedClaims);
    }


    /**
     * Test we can set the non-string standard claims
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testStandardClaimTypesCanBeSet(): void
    {
        $translate = [
            'updated_at' => [
                'type' => 'int',
                'last_updated',
            ],
            'email_verified' => [
                'type' => 'bool',
                'is_email_verified',
            ],
            'phone_number_verified' => [
                'type' => 'bool',
                'is_phone_number_verified',
            ],
            'address' => [
                'type' => 'json',
                'claims' => [
                    'country' => ['country'],
                    'postal_code' => ['postal'],
                ],
            ],
        ];
        $userAttributes = (new Attributes())->normalizeAttributesArray(
            [
                'country' => 'CA',
                'postal' => '93105',
                'postalAddress' => 'should not appear in mapping',
                'last_updated' => '12341',
                'is_email_verified' => 'yes',
                'is_phone_number_verified' => 'no',
            ],
        );
        $claimTranslator = $this->mock([], $translate);
        $releasedClaims = $claimTranslator->extract(
            ['address', 'profile', 'email', 'phone'],
            $userAttributes,
        );
        $expectedClaims = [
            'address' => [
                'country' => 'CA',
                'postal_code' => '93105',
            ],
            'updated_at' => 12341,
            'email_verified' => true,
            'phone_number_verified' => false,
        ];

        $this->assertSame($expectedClaims, $releasedClaims);
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testInvalidTypeConversion(): void
    {
        $this->expectExceptionMessage("Cannot convert '7890F' to int");
        $claimSet = new ClaimSetEntity('typeConversion', ['testClaim',]);
        $translate = [
            'testClaim' => [
                'type' => 'int',
                'testClaim',
            ],
        ];
        $userAttributes = (new Attributes())->normalizeAttributesArray(['testClaim' => '7890F',]);
        $claimTranslator = $this->mock([$claimSet], $translate);
        $claimTranslator->extract(['typeConversion'], $userAttributes);
    }


    public function testConvertsIntegerSubjectClaimToString(): void
    {
        $releasedClaims = $this->mock()->extract(
            ['openid'],
            ['uid' => [123]],
        );

        $this->assertSame(['sub' => '123'], $releasedClaims);
    }


    #[DataProvider('unsafeStringValuesProvider')]
    public function testRejectsUnsafeStringConversion(mixed $value, string $type): void
    {
        $claimSet = new ClaimSetEntity('typeConversion', ['testClaim']);
        $translate = [
            'testClaim' => [
                'type' => 'string',
                'testAttribute',
            ],
        ];

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(sprintf('Cannot safely convert %s to string', $type));

        $this->mock([$claimSet], $translate)->extract(
            ['typeConversion'],
            ['testAttribute' => [$value]],
        );
    }


    public static function unsafeStringValuesProvider(): array
    {
        return [
            'null' => [null, 'null'],
            'non-stringable object' => [new stdClass(), 'stdClass'],
        ];
    }


    public function testRejectsEmptySubjectClaimAfterStringConversion(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("The 'sub' claim must be a non-empty string");

        $this->mock()->extract(
            ['openid'],
            ['uid' => [false]],
        );
    }


    /**
     * Only the claims the granted scopes release are translated: an attribute value which can not be converted
     * fails a release which includes its claim, directly or as a member of a 'json' claim, and no other -- not
     * one which leaves the claim to a scope that was not granted, nor one of a claim no scope releases.
     */
    #[DataProvider('scopeReleasingAnUnconvertibleValueProvider')]
    public function testTranslatesOnlyTheClaimsTheGrantedScopesRelease(string $scope): void
    {
        $translate = [
            'org' => ['orgAttribute'],
            'level' => ['type' => 'int', 'attributes' => ['levelAttribute']],
            'assurance' => [
                'type' => 'json',
                'claims' => ['level' => ['type' => 'int', 'attributes' => ['levelAttribute']]],
            ],
            'unreleased' => ['type' => 'int', 'attributes' => ['levelAttribute']],
        ];
        $claimTranslator = $this->mock(
            [
                new ClaimSetEntity('org', ['org']),
                new ClaimSetEntity('level', ['level']),
                new ClaimSetEntity('assurance', ['assurance']),
            ],
            $translate,
        );
        $userAttributes = ['uid' => ['u1'], 'orgAttribute' => ['Example'], 'levelAttribute' => ['7890F']];

        $this->assertSame(
            ['sub' => 'u1', 'org' => 'Example'],
            $claimTranslator->extract(['openid', 'org', 'unknown'], $userAttributes),
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Cannot convert '7890F' to int");

        $claimTranslator->extract(['org', $scope], $userAttributes);
    }


    /**
     * @return array<string, array{0: string}>
     */
    public static function scopeReleasingAnUnconvertibleValueProvider(): array
    {
        return [
            'a claim' => ['level'],
            'a member of a json claim' => ['assurance'],
        ];
    }


    /**
     * A caller which carries only some of the released claims (the JWT access token) names them, and the others
     * are not translated, so a value of theirs which can not be converted does not fail it. A named claim still
     * needs a granted scope which releases it, 'sub' included.
     */
    public function testTranslatesOnlyTheNamedClaimsOfThoseTheScopesRelease(): void
    {
        $claimTranslator = $this->mock(
            [new ClaimSetEntity('bundle', ['org', 'level']), new ClaimSetEntity('other', ['unit'])],
            [
                'org' => ['orgAttribute'],
                'level' => ['type' => 'int', 'attributes' => ['levelAttribute']],
                'unit' => ['unitAttribute'],
            ],
        );
        $userAttributes = [
            'uid' => ['u1'],
            'orgAttribute' => ['Example'],
            'levelAttribute' => ['7890F'],
            'unitAttribute' => ['Unit'],
        ];

        $this->assertSame(
            ['org' => 'Example'],
            $claimTranslator->extract(['openid', 'bundle'], $userAttributes, ['org', 'unit']),
        );
        $this->assertSame(
            ['sub' => 'u1'],
            $claimTranslator->extract(['openid', 'bundle'], $userAttributes, ['sub']),
        );
        $this->assertSame(['org' => 'Example'], $claimTranslator->extract(['bundle'], $userAttributes, ['org', 'sub']));
        $this->assertSame([], $claimTranslator->extract(['openid', 'bundle'], $userAttributes, []));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Cannot convert '7890F' to int");

        $claimTranslator->extract(['bundle'], $userAttributes, ['org', 'level']);
    }


    /**
     * A claim is released under a non-empty string name which stays a string as an array key, so an integer, a
     * decimal integer string or an empty name in a claim set or a claims request releases nothing and is not
     * translated: the 'int' entry under key 0 would throw on its value. Nor is it advertised in claims_supported
     * (both found by review).
     */
    public function testReleasesNoClaimUnderAnIntegerOrAnEmptyName(): void
    {
        $claimTranslator = $this->mock(
            [new ClaimSetEntity('odd', ['0', 1, '', 'org'])],
            [
                0 => ['type' => 'int', 'attributes' => ['levelAttribute']],
                1 => ['orgAttribute'],
                '' => ['orgAttribute'],
                'org' => ['orgAttribute'],
            ],
        );
        $userAttributes = ['orgAttribute' => ['Example'], 'levelAttribute' => ['high']];

        $this->assertSame(['org' => 'Example'], $claimTranslator->extract(['odd'], $userAttributes));
        $this->assertSame([], $claimTranslator->extract(['odd'], $userAttributes, ['0', '1', '']));
        $this->assertSame(
            ['org' => 'Example'],
            $claimTranslator->extractAdditionalUserInfoClaims(
                ['userinfo' => ['0' => null, '1' => null, '' => null, 'org' => null]],
                $userAttributes,
            ),
        );

        $supportedClaims = $claimTranslator->getSupportedClaims();
        $this->assertContains('org', $supportedClaims);
        $this->assertNotContains(0, $supportedClaims);
        $this->assertNotContains(1, $supportedClaims);
        $this->assertNotContains('', $supportedClaims);
    }


    /**
     * The 'claims' request parameter translates only the claims it asks for, for the ID token and the UserInfo
     * response alike.
     */
    public function testTranslatesOnlyTheClaimsAClaimsRequestAsksFor(): void
    {
        $claimTranslator = $this->mock([], ['level' => ['type' => 'int', 'attributes' => ['levelAttribute']]]);
        $userAttributes = ['cn' => ['bob'], 'levelAttribute' => ['7890F']];

        $this->assertSame(
            ['name' => 'bob'],
            $claimTranslator->extractAdditionalUserInfoClaims(['userinfo' => ['name' => null]], $userAttributes),
        );
        $this->assertSame(
            ['name' => 'bob'],
            $claimTranslator->extractAdditionalIdTokenClaims(
                ['id_token' => ['name' => ['essential' => true]]],
                $userAttributes,
            ),
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Cannot convert '7890F' to int");

        $claimTranslator->extractAdditionalIdTokenClaims(
            ['id_token' => ['name' => null, 'level' => null]],
            $userAttributes,
        );
    }


    /**
     * An attribute is an array of values, and each value a claim releases a single one: a value which is an array (an
     * authentication processing filter can set one) would make a single-valued claim a list and a list claim a
     * list holding a list, so it is refused, whatever the claim's type and for a member of a 'json' claim too. The
     * error names the claim, a member as `claim.member`, and the attribute.
     */
    #[DataProvider('arrayValueProvider')]
    public function testRefusesAReleasedValueWhichIsAnArray(array $mapping, array $attributeValues, string $path): void
    {
        $claimTranslator = $this->mock([new ClaimSetEntity('level', ['level'])], ['level' => $mapping]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            sprintf(
                "The '%s' claim can not be translated: a value of attribute 'levelAttribute' is an array, not a " .
                'single value',
                $path,
            ),
        );

        $claimTranslator->extract(['level'], ['levelAttribute' => $attributeValues]);
    }


    /**
     * @return array<string, array{0: array, 1: array, 2: string}>
     */
    public static function arrayValueProvider(): array
    {
        $multiValued = ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED;
        $attributes = ['levelAttribute'];

        return [
            'the first value of a single-valued claim' => [$attributes, [['a', 'b'], 'c'], 'level'],
            'an associative array' => [$attributes, [['key' => 'a']], 'level'],
            'an empty array' => [$attributes, [[]], 'level'],
            'an int claim' => [['type' => 'int', 'attributes' => $attributes], [['1', '2']], 'level'],
            'a type which converts nothing' => [['type' => 'raw', 'attributes' => $attributes], [['a']], 'level'],
            'a later value of a list claim' => [
                [$multiValued => true, 'attributes' => $attributes],
                ['a', ['b', 'c']],
                'level',
            ],
            'a bool list claim' => [
                ['type' => 'bool', $multiValued => true, 'attributes' => $attributes],
                [['1']],
                'level',
            ],
            'a member of a json claim' => [
                ['type' => 'json', 'claims' => ['member' => $attributes]],
                [['a']],
                'level.member',
            ],
            'a list member of a json claim' => [
                ['type' => 'json', 'claims' => ['member' => [$multiValued => true, 'attributes' => $attributes]]],
                ['a', ['b']],
                'level.member',
            ],
            'a member of a json member' => [
                [
                    'type' => 'json',
                    'claims' => ['outer' => ['type' => 'json', 'claims' => ['member' => $attributes]]],
                ],
                [['a']],
                'level.outer.member',
            ],
        ];
    }


    /**
     * Nor is an attribute which is not an array of values: it has no first value for a single-valued claim to
     * take, and would make a list claim a single value.
     */
    #[DataProvider('attributeWhichIsNotAnArrayProvider')]
    public function testRefusesAnAttributeWhichIsNotAnArrayOfValues(bool $multiValued, mixed $attributeValue): void
    {
        $claimTranslator = $this->mock(
            [new ClaimSetEntity('level', ['level'])],
            [
                'level' => [
                    ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => $multiValued,
                    'attributes' => ['levelAttribute'],
                ],
            ],
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            "The 'level' claim can not be translated: attribute 'levelAttribute' is not an array of values",
        );

        $claimTranslator->extract(['level'], ['levelAttribute' => $attributeValue]);
    }


    /**
     * @return array<string, array{0: bool, 1: mixed}>
     */
    public static function attributeWhichIsNotAnArrayProvider(): array
    {
        return [
            'a string, for a single-valued claim' => [false, 'a'],
            'a string, for a list claim' => [true, 'a'],
            'null' => [false, null],
            'an integer, for a list claim' => [true, 7],
            'an object' => [false, new stdClass()],
        ];
    }


    /**
     * The refusal holds wherever a claim is translated: for 'sub' and an identity claim, ahead of the check that
     * they are non-empty strings, for the subject alone, and for a claim the 'claims' request parameter asks for.
     */
    #[DataProvider('everyTranslationOfAnArrayValueProvider')]
    public function testRefusesAnArrayValueWhereverAClaimIsTranslated(
        string $method,
        array $arguments,
        string $claim,
        string $attribute,
    ): void {
        $claimTranslator = $this->mock(
            [],
            ['voperson_id' => ['voPersonID'], 'level' => ['levelAttribute']],
            ['voperson_id'],
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            sprintf(
                "The '%s' claim can not be translated: a value of attribute '%s' is an array, not a single value",
                $claim,
                $attribute,
            ),
        );

        $claimTranslator->$method(...$arguments);
    }


    /**
     * @return array<string, array{0: string, 1: array, 2: string, 3: string}>
     */
    public static function everyTranslationOfAnArrayValueProvider(): array
    {
        $array = [['v1', 'v2']];

        return [
            "'sub'" => ['extract', [['openid'], ['uid' => $array]], 'sub', 'uid'],
            "'sub' alone" => ['extractSubject', [['uid' => $array]], 'sub', 'uid'],
            'an identity claim' => [
                'extract',
                [['openid'], ['uid' => ['u1'], 'voPersonID' => $array]],
                'voperson_id',
                'voPersonID',
            ],
            'a claim requested for the UserInfo response' => [
                'extractAdditionalUserInfoClaims',
                [['userinfo' => ['level' => null]], ['levelAttribute' => $array]],
                'level',
                'levelAttribute',
            ],
            'a claim requested for the ID token' => [
                'extractAdditionalIdTokenClaims',
                [['id_token' => ['level' => null]], ['levelAttribute' => $array]],
                'level',
                'levelAttribute',
            ],
        ];
    }


    /**
     * Only the values a claim releases are looked at: a single-valued claim takes its attribute's first value
     * whatever the later ones are, and an attribute which only a claim not released is read from fails nothing.
     * The attribute's keys play no part: a list claim takes every value, in order, as a list (keys found by
     * review).
     */
    public function testLooksOnlyAtTheValuesAClaimReleases(): void
    {
        $claimTranslator = $this->mock(
            [new ClaimSetEntity('org', ['org', 'unit']), new ClaimSetEntity('level', ['level', 'rank'])],
            [
                'org' => ['orgAttribute'],
                'unit' => [
                    ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true,
                    'attributes' => ['unitAttribute'],
                ],
                'level' => ['levelAttribute'],
                'rank' => ['rankAttribute'],
            ],
        );
        $userAttributes = [
            'orgAttribute' => ['primary' => 'Example', 'secondary' => ['a', 'b']],
            'unitAttribute' => ['first' => 'Unit A', 'second' => 'Unit B'],
            'levelAttribute' => [['high']],
            'rankAttribute' => 'first',
        ];

        $this->assertSame(
            ['org' => 'Example', 'unit' => ['Unit A', 'Unit B']],
            $claimTranslator->extract(['org'], $userAttributes),
        );
        $this->assertSame(
            ['org' => 'Example'],
            $claimTranslator->extractAdditionalUserInfoClaims(['userinfo' => ['org' => null]], $userAttributes),
        );
    }


    /**
     * A single-valued claim takes its attribute's first value, and that is the value checked, wherever the array's
     * internal pointer is (found by review).
     */
    public function testTakesTheFirstValueWhereverTheArrayPointerIs(): void
    {
        $claimTranslator = $this->mock([new ClaimSetEntity('org', ['org'])], ['org' => ['orgAttribute']]);
        $valid = ['Example', ['later']];
        next($valid);
        $malformed = [['first'], 'later'];
        next($malformed);

        $this->assertSame(['org' => 'Example'], $claimTranslator->extract(['org'], ['orgAttribute' => $valid]));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            "The 'org' claim can not be translated: a value of attribute 'orgAttribute' is an array, not a single " .
            'value',
        );

        $claimTranslator->extract(['org'], ['orgAttribute' => $malformed]);
    }


    /**
     * PHP keeps an attribute named '123' under the integer key 123, and an entry may name it so, or by a float
     * which PHP takes for that key (both found by review).
     */
    public function testReadsAnAttributeUnderAnIntegerKey(): void
    {
        $this->assertSame(
            ['org' => 'Example'],
            $this->mock([new ClaimSetEntity('org', ['org'])], ['org' => [123]])
                ->extract(['org'], ['123' => ['Example']]),
        );
        $this->assertSame(
            ['org' => 'Example'],
            $this->mock([new ClaimSetEntity('org', ['org'])], ['org' => [123.0]])
                ->extract(['org'], ['123' => ['Example']]),
        );
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testExtractRequestClaimsUserInfo(): void
    {
        $claimTranslator = $this->mock();
        $requestClaims = [
            "userinfo" => [
                "name" => ['essential' => true],
            ],
        ];

        $claims = $claimTranslator->extractAdditionalUserInfoClaims($requestClaims, ['cn' => ['bob']]);
        $this->assertEquals(['name' => 'bob'], $claims);
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testExtractRequestClaimsIdToken(): void
    {
        $claimTranslator = $this->mock();
        $requestClaims = [
            "id_token" => [
                "name" => ['essential' => true],
            ],
        ];

        $claims = $claimTranslator->extractAdditionalIdTokenClaims($requestClaims, ['displayName' => ['bob']]);
        $this->assertEquals(['name' => 'bob'], $claims);
    }


    public function testCanGetSupportedClaims(): void
    {
        $translate = [
            'custom' => [
                'type' => 'int',
                'custom_attr',
            ],
        ];

        $this->assertTrue(in_array('custom', $this->mock([], $translate)->getSupportedClaims(), true));
    }


    public function testCanUnsetClaimWhichIsSupportedByDefault(): void
    {
        $this->assertTrue(in_array('nickname', $this->mock()->getSupportedClaims(), true));

        $translate = ['nickname' => []];
        $this->assertFalse(in_array('nickname', $this->mock([], $translate)->getSupportedClaims(), true));
    }


    /**
     * The multi-value setting is no translation, so an entry which holds it alone is not advertised: an entry
     * replaces the default one whole, so `'nickname' => ['multi_valued' => false]` leaves nickname nothing to read.
     */
    public function testAnEntryHoldingTheMultiValueSettingAloneIsNotSupported(): void
    {
        $translate = ['nickname' => [ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => false]];
        $this->assertNotContains('nickname', $this->mock([], $translate)->getSupportedClaims());

        $translate['nickname'][] = 'eduPersonNickname';
        $this->assertContains('nickname', $this->mock([], $translate)->getSupportedClaims());
    }


    public function testCanReleaseMultiValueClaims(): void
    {
        $claimSet = new ClaimSetEntity(
            'multiValueClaimsScope',
            ['multiValueClaim'],
        );

        $translate = [
            'multiValueClaim' => [
                ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true,
                'attributes' => ['multiValueAttribute'],
            ],
        ];

        $userAttributes = [
            'multiValueAttribute' => ['1', '2', '3'],
        ];


        $claimTranslator = $this->mock([$claimSet], $translate);

        $releasedClaims = $claimTranslator->extract(
            ['multiValueClaimsScope'],
            $userAttributes,
        );

        $expectedClaims = [
            'multiValueClaim' => ['1', '2', '3'],
        ];

        $this->assertSame($expectedClaims, $releasedClaims);
    }


    public function testWillReleaseSingleValueClaimsIfMultiValueNotAllowed(): void
    {
        $claimSet = new ClaimSetEntity(
            'multiValueClaimsScope',
            ['multiValueClaim'],
        );


        $translate = [
            'multiValueClaim' => [
                'multiValueAttribute',
            ],
        ];

        $userAttributes = [
            'multiValueAttribute' => ['1', '2', '3'],
        ];

        $claimTranslator = $this->mock([$claimSet], $translate);

        $releasedClaims = $claimTranslator->extract(
            ['multiValueClaimsScope'],
            $userAttributes,
        );

        $expectedClaims = ['multiValueClaim' => '1'];

        $this->assertSame($expectedClaims, $releasedClaims);

        // An explicit false is the default.
        $translate['multiValueClaim'] = [
            ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => false,
            'attributes' => ['multiValueAttribute'],
        ];

        $this->assertSame(
            $expectedClaims,
            $this->mock([$claimSet], $translate)->extract(['multiValueClaimsScope'], $userAttributes),
        );

        // So is any value but true, which the factory refuses.
        $translate['multiValueClaim'][ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED] = 'yes';

        $this->assertSame(
            $expectedClaims,
            $this->mock([$claimSet], $translate)->extract(['multiValueClaimsScope'], $userAttributes),
        );
    }


    /**
     * Issue #360: a scope carrying a claim which is a list next to one which is not. Each claim has its own
     * shape -- the list a list even with a single value, the other a string even with several -- and keeps it
     * under every scope which releases it, alone or with others.
     */
    public function testEachClaimHasItsOwnShapeUnderEveryScope(): void
    {
        $translate = [
            'eduperson_principal_name' => [
                ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => false,
                'attributes' => ['eduPersonPrincipalName'],
            ],
            'eduperson_affiliation' => [
                ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true,
                'attributes' => ['eduPersonAffiliation'],
            ],
        ];
        $claimTranslator = $this->mock(
            [
                new ClaimSetEntity('eduperson', ['eduperson_principal_name', 'eduperson_affiliation']),
                new ClaimSetEntity('affiliation', ['eduperson_affiliation']),
                new ClaimSetEntity('principal', ['eduperson_principal_name']),
            ],
            $translate,
        );
        $userAttributes = [
            'eduPersonPrincipalName' => ['u1@example.org', 'u1-old@example.org'],
            'eduPersonAffiliation' => ['member'],
        ];

        foreach ([['eduperson'], ['affiliation', 'principal'], ['principal', 'eduperson']] as $scopes) {
            $released = $claimTranslator->extract($scopes, $userAttributes);

            $this->assertSame('u1@example.org', $released['eduperson_principal_name'] ?? null);
            $this->assertSame(['member'], $released['eduperson_affiliation'] ?? null);
        }
    }


    /**
     * A member of a 'json' claim takes its shape from its own entry, as a claim does; a member is no claim, so one
     * named like a standard claim is a list when its entry says so, and one named like a list claim is not a list
     * unless its own entry says so.
     */
    public function testAMemberOfAJsonClaimTakesItsShapeFromItsOwnEntry(): void
    {
        $translate = [
            'eduperson_affiliation' => [
                ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true,
                'attributes' => ['eduPersonAffiliation'],
            ],
            'contact' => [
                'type' => 'json',
                'claims' => [
                    'email' => [ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true, 'attributes' => ['mail']],
                    'eduperson_affiliation' => ['eduPersonAffiliation'],
                ],
            ],
        ];
        $userAttributes = [
            'mail' => ['m1', 'm2'],
            'eduPersonAffiliation' => ['member', 'staff'],
        ];

        $this->assertSame(
            ['contact' => ['email' => ['m1', 'm2'], 'eduperson_affiliation' => 'member']],
            $this->mock([new ClaimSetEntity('contact', ['contact'])], $translate)
                ->extract(['contact'], $userAttributes),
        );
    }


    /**
     * In an entry which lists its attributes directly, the setting sits in that list and is not taken for an
     * attribute to read: `true` would be looked up as the attribute key 1.
     */
    public function testTheSettingInAnEntryListingItsAttributesIsNoAttribute(): void
    {
        $translate = ['claim' => [ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true, 'attribute']];
        $userAttributes = [1 => ['not this'], 'attribute' => ['a1', 'a2']];

        $this->assertSame(
            ['claim' => ['a1', 'a2']],
            $this->mock([new ClaimSetEntity('scope', ['claim'])], $translate)->extract(['scope'], $userAttributes),
        );
    }


    public function testWillReleaseSingleValueClaimsForMandatorySingleValueClaims(): void
    {
        $claimSet = new ClaimSetEntity(
            'customScope',
            [
                'sub',
                'name',
                'given_name',
                'family_name',
                'middle_name',
                'nickname',
                'preferred_username',
                'profile',
                'picture',
                'website',
                'email',
                'email_verified',
                'gender',
                'birthdate',
                'zoneinfo',
                'locale',
                'phone_number',
                'phone_number_verified',
                'address',
                'updated_at',
            ],
        );

        $translate = [
            'sub' => ['subAttribute'],
            'name' => ['nameAttribute'],
            'given_name' => ['givenNameAttribute'],
            'family_name' => ['familyNameAttribute'],
            'middle_name' => ['middleNameAttribute'],
            'nickname' => ['nicknameAttribute'],
            'preferred_username' => ['preferredUsernameAttribute'],
            'profile' => ['profileAttribute'],
            'picture' => ['pictureAttribute'],
            'website' => ['websiteAttribute'],
            'email' => ['emailAttribute'],
            'email_verified' => ['emailVerifiedAttribute'],
            'gender' => ['genderAttribute'],
            'birthdate' => ['birthdateAttribute'],
            'zoneinfo' => ['zoneinfoAttribute'],
            'locale' => ['localeAttribute'],
            'phone_number' => ['phoneNumberAttribute'],
            'phone_number_verified' => ['phoneNumberVerifiedAttribute'],
            'address' => [
                'type' => 'json',
                'claims' => [
                    'formatted' => ['addressAttribute'],
                ],
            ],
            'updated_at' => ['updatedAtAttribute'],
        ];

        $userAttributes = [
            'subAttribute' => ['id1', 'id2', 'id3'],
            'nameAttribute' => ['name1', 'name2', 'name3'],
            'givenNameAttribute' => ['givenName1', 'givenName2', 'givenName3'],
            'familyNameAttribute' => ['familyName1', 'familyName2', 'familyName3'],
            'middleNameAttribute' => ['middleName1', 'middleName2', 'middleName3'],
            'nicknameAttribute' => ['nickname1', 'nickname2', 'nickname3'],
            'preferredUsernameAttribute' => ['preferredUsername1', 'preferredUsername2', 'preferredUsername3'],
            'profileAttribute' => ['profileUrl1', 'profileUrl2', 'profileUrl3'],
            'pictureAttribute' => ['pictureUrl1', 'pictureUrl2', 'pictureUrl3'],
            'websiteAttribute' => ['websiteUrl1', 'websiteUrl2', 'websiteUrl3'],
            'emailAttribute' => ['email1', 'email2', 'email3'],
            'emailVerifiedAttribute' => [true, false],
            'genderAttribute' => ['gender1', 'gender2', 'gender3'],
            'birthdateAttribute' => ['birthdate1', 'birthdate2', 'birthdate3'],
            'zoneinfoAttribute' => ['zoneinfo1', 'zoneinfo2', 'zoneinfo3'],
            'localeAttribute' => ['locale1', 'locale2', 'locale3'],
            'phoneNumberAttribute' => ['phoneNumber1', 'phoneNumber2', 'phoneNumber3'],
            'phoneNumberVerifiedAttribute' => [true, false],
            'addressAttribute' => ['address1', 'address2', 'address3'],
            'updatedAtAttribute' => [123, 456],
        ];

        // Every entry asks for a list, which a standard claim never is.
        $translate = array_map(
            fn(array $mapping): array => [ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true, ...$mapping],
            $translate,
        );

        $claimTranslator = $this->mock([$claimSet], $translate);

        $releasedClaims = $claimTranslator->extract(
            ['customScope'],
            $userAttributes,
        );

        $expectedClaims = [
            'sub' => 'id1',
            'name' => 'name1',
            'given_name' => 'givenName1',
            'family_name' => 'familyName1',
            'middle_name' => 'middleName1',
            'nickname' => 'nickname1',
            'preferred_username' => 'preferredUsername1',
            'profile' => 'profileUrl1',
            'picture' => 'pictureUrl1',
            'website' => 'websiteUrl1',
            'email' => 'email1',
            'email_verified' => true,
            'gender' => 'gender1',
            'birthdate' => 'birthdate1',
            'zoneinfo' => 'zoneinfo1',
            'locale' => 'locale1',
            'phone_number' => 'phoneNumber1',
            'phone_number_verified' => true,
            'address' => ['formatted' => 'address1'],
            'updated_at' => 123,
        ];

        $this->assertEquals($expectedClaims, $releasedClaims);
    }


    /**
     * The 'openid' scope releases the subject, which is 'sub' and the identity claims next to it; 'sub' is
     * there once whatever the list says.
     */
    public function testTheOpenIdScopeReleasesTheIdentityClaimsNextToTheSubject(): void
    {
        $this->assertSame(['sub'], $this->mock()->getClaimSet('openid')?->getClaims());

        $claimTranslator = $this->mock(
            [],
            ['voperson_id' => ['voPersonID']],
            ['voperson_id', 'sub', 'voperson_id'],
        );

        $this->assertSame(['sub', 'voperson_id'], $claimTranslator->getClaimSet('openid')?->getClaims());
        $this->assertSame(
            ['sub' => 'u1', 'voperson_id' => 'v1'],
            $claimTranslator->extract(['openid'], ['uid' => ['u1'], 'voPersonID' => ['v1']]),
        );
    }


    /**
     * Like the standard single-value claims, an identity claim is translated to its first value even when its
     * entry asks for a list, since it identifies the subject in every location it is released in.
     */
    public function testAnIdentityClaimIsSingleValuedEvenWhereItsEntryAsksForAList(): void
    {
        $claimSet = new ClaimSetEntity('bundle', ['voperson_id', 'eduperson_entitlement']);
        $translate = [
            'voperson_id' => [
                ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true,
                'attributes' => ['voPersonID'],
            ],
            'eduperson_entitlement' => [
                ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true,
                'attributes' => ['eduPersonEntitlement'],
            ],
        ];
        $userAttributes = [
            'uid' => ['u1'],
            'voPersonID' => ['v1', 'v2'],
            'eduPersonEntitlement' => ['e1', 'e2'],
        ];

        $this->assertSame(
            ['voperson_id' => ['v1', 'v2'], 'eduperson_entitlement' => ['e1', 'e2']],
            $this->mock([$claimSet], $translate)->extract(['bundle'], $userAttributes),
        );

        $claimTranslator = $this->mock([$claimSet], $translate, ['voperson_id']);

        $this->assertSame(
            ['voperson_id' => 'v1', 'eduperson_entitlement' => ['e1', 'e2']],
            $claimTranslator->extract(['bundle'], $userAttributes),
        );
        $this->assertSame(
            ['sub' => 'u1', 'voperson_id' => 'v1'],
            $claimTranslator->extract(['openid'], $userAttributes),
        );
    }


    /**
     * A claim counts as translated when the translation can yield a value: at least one attribute, or for a
     * 'json' claim at least one sub-claim, read the way the translation reads the mapping (legacy list,
     * 'attributes' key, 'type').
     */
    #[DataProvider('claimTranslationProvider')]
    public function testTellsWhetherAClaimHasATranslationWhichCanYieldAValue(array $mapping, bool $expected): void
    {
        $this->assertSame($expected, $this->mock([], ['claim' => $mapping])->isClaimTranslated('claim'));
    }


    /**
     * @return array<string, array{0: array, 1: bool}>
     */
    public static function claimTranslationProvider(): array
    {
        return [
            'legacy attribute list' => [['attribute'], true],
            'attributes key' => [['type' => 'string', 'attributes' => ['attribute']], true],
            'json with a sub-claim' => [['type' => 'json', 'claims' => ['sub' => ['attribute']]], true],
            'emptied' => [[], false],
            'type only' => [['type' => 'int'], false],
            'attributes key, empty' => [['type' => 'string', 'attributes' => []], false],
            'json without sub-claims' => [['type' => 'json', 'claims' => []], false],
            'json without the claims key' => [['type' => 'json'], false],
            'the multi-value setting alone' => [[ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true], false],
            'the multi-value setting, attributes listed directly' => [
                [ClaimTranslatorExtractor::MAPPING_KEY_MULTI_VALUED => true, 'attribute'],
                true,
            ],
            'json whose sub-claims translate nothing' => [['type' => 'json', 'claims' => ['level' => []]], false],
            'json with a nested json which translates' => [
                ['type' => 'json', 'claims' => ['inner' => ['type' => 'json', 'claims' => ['leaf' => ['attr']]]]],
                true,
            ],
            'json with a nested json which translates nothing' => [
                ['type' => 'json', 'claims' => ['inner' => ['type' => 'json', 'claims' => ['leaf' => []]]]],
                false,
            ],
        ];
    }


    public function testAClaimWithoutATableEntryIsNotTranslated(): void
    {
        $this->assertFalse($this->mock()->isClaimTranslated('unknown_claim'));
        // A default the module ships empty.
        $this->assertFalse($this->mock()->isClaimTranslated('middle_name'));
        $this->assertTrue($this->mock()->isClaimTranslated('email'));
    }


    /**
     * An identity claim is held to the rule 'sub' is held to: released only as a non-empty string. The
     * translation alone can not guarantee it -- an attribute with no value, or with an empty first value, yields
     * '' -- so the extraction refuses such a value (found by review). The valid subject-like value "0" passes, and
     * a claim which is not an identity claim is not held to the rule. A value which is an array is refused for
     * every claim (testRefusesAnArrayValueWhereverAClaimIsTranslated()).
     */
    #[DataProvider('unusableIdentityClaimValueProvider')]
    public function testRefusesAnIdentityClaimWhichIsNotANonEmptyString(array $attributeValue): void
    {
        $translate = ['voperson_id' => ['voPersonID'], 'other' => ['otherAttribute']];
        $claimTranslator = $this->mock([], $translate, ['voperson_id']);

        // Not an identity claim: the same value passes through as before.
        $this->assertArrayHasKey(
            'other',
            $this->mock([new ClaimSetEntity('scope', ['other'])], $translate, ['voperson_id'])
                ->extract(['scope'], ['otherAttribute' => $attributeValue]),
        );
        $this->assertSame(
            ['sub' => 'u1', 'voperson_id' => '0'],
            $claimTranslator->extract(['openid'], ['uid' => ['u1'], 'voPersonID' => ['0']]),
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("The 'voperson_id' identity claim must be a non-empty string");

        $claimTranslator->extract(['openid'], ['uid' => ['u1'], 'voPersonID' => $attributeValue]);
    }


    /**
     * @return array<string, array{0: array}>
     */
    public static function unusableIdentityClaimValueProvider(): array
    {
        return [
            'no value' => [[]],
            'an empty string' => [['']],
        ];
    }


    public function testRefusesAnIdentityClaimWhichIsNotANonEmptyStringWhenIndividuallyRequested(): void
    {
        $claimTranslator = $this->mock([], ['voperson_id' => ['voPersonID']], ['voperson_id']);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("The 'voperson_id' identity claim must be a non-empty string");

        $claimTranslator->extractAdditionalUserInfoClaims(
            ['userinfo' => ['voperson_id' => null]],
            ['voPersonID' => ['']],
        );
    }


    /**
     * A subject comparison (an `id_token_hint` match before the authentication processing filters have run, the
     * RP association) needs 'sub' and nothing else: the identity claims are left out, so an attribute a filter
     * still has to supply, or an invalid value of one, can not fail it (found by review). A mapped 'sub' which is
     * not a non-empty string is still refused, as extract() refuses it.
     */
    public function testExtractsTheSubjectAloneWithoutTheIdentityClaims(): void
    {
        $claimTranslator = $this->mock([], ['voperson_id' => ['voPersonID']], ['voperson_id']);

        $this->assertSame('u1', $claimTranslator->extractSubject(['uid' => ['u1'], 'voPersonID' => []]));
        $this->assertSame('u1', $claimTranslator->extractSubject(['uid' => ['u1'], 'voPersonID' => [['v1', 'v2']]]));
        $this->assertSame('0', $claimTranslator->extractSubject(['uid' => ['0']]));
        $this->assertNull($claimTranslator->extractSubject(['voPersonID' => ['v1']]));
        $this->assertNull($this->mock([], ['sub' => []])->extractSubject(['uid' => ['u1']]));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("The 'sub' claim must be a non-empty string");

        $claimTranslator->extractSubject(['uid' => [false]]);
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\ClaimSetEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Utils\Attributes;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor
 */
class ClaimTranslatorExtractorTest extends TestCase
{
    protected static string $userIdAttr = 'uid';
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
        array $allowedMultiValueClaims = [],
    ): ClaimTranslatorExtractor {
        return new ClaimTranslatorExtractor(
            self::$userIdAttr,
            $this->claimSetEntityFactoryStub,
            $claimSets,
            $translationTable,
            $allowedMultiValueClaims,
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

    public function testCanReleaseMultiValueClaims(): void
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


        $claimTranslator = $this->mock([$claimSet], $translate, ['multiValueClaim']);

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

        $claimTranslator = $this->mock([$claimSet], $translate, []);

        $releasedClaims = $claimTranslator->extract(
            ['multiValueClaimsScope'],
            $userAttributes,
        );

        $expectedClaims = ['multiValueClaim' => '1'];

        $this->assertSame($expectedClaims, $releasedClaims);
    }

    public function testWillReleaseSingleValueClaimsForMandatorySingleValueClaims(): void
    {

        // TODO mivanci v7 Test for mandatory single value claims in other scopes, as per
        // \SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor::MANDATORY_SINGLE_VALUE_CLAIMS
        $claimSet = new ClaimSetEntity(
            'customScopeWithSubClaim',
            ['sub'],
        );

        $translate = [
            'sub' => [
                'subAttribute',
            ],
        ];

        $userAttributes = [
            'subAttribute' => ['1', '2', '3'],
        ];

        $claimTranslator = $this->mock([$claimSet], $translate, ['sub']);

        $releasedClaims = $claimTranslator->extract(
            ['openid'],
            $userAttributes,
        );

        $expectedClaims = ['sub' => '1'];

        $this->assertSame($expectedClaims, $releasedClaims);
    }
}

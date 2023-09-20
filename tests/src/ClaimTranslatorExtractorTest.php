<?php

namespace SimpleSAML\Test\Module\oidc;

use SimpleSAML\Module\oidc\Entity\ClaimSetEntity;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Utils\Attributes;

/**
 * @covers \SimpleSAML\Module\oidc\ClaimTranslatorExtractor
 */
class ClaimTranslatorExtractorTest extends TestCase
{
    protected static string $userIdAttr = 'uid';
    /**
     * Test various type conversions work, including types in subobjects
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
            //Test oid style claim names is not interpreted as a type of 'urn'
            'urn:oid:2.5.4.3'
            ]
        );
        $translate = [
            'intClaim' => [
                'type' => 'int',
                'attributes' => ['intAttribute']
            ],
            'boolClaim1' => [
                'type' => 'bool',
                'attributes' => ['boolAttribute1']
            ],
            'boolClaimYes' => [
                'type' => 'bool',
                'attributes' => ['boolAttributeYes']
            ]
            ,
            'boolClaimTrue' => [
                'type' => 'bool',
                'attributes' => ['boolAttributeTrue']
            ],
            'boolClaimOther' => [
                'type' => 'bool',
                'attributes' => ['boolAttributeOther']
            ],
            'defaultClaim' => ['stringAttribute'],
            'stringClaim' => ['type' => 'string', 'attributes' => ['stringAttribute']],
            'jsonClaim' => [
                'type' => 'json',
                'claims' => [
                    'subIntClaim' => [
                        'type' => 'int',
                        'attributes' => ['intAttribute']
                    ],
                    'subBoolClaim' => [
                        'type' => 'bool',
                        'attributes' => ['boolAttribute1']
                    ],
                    'subStringClaim' => ['stringAttribute'],
                ]
            ],
            'urn:oid:2.5.4.3' => ['stringAttribute']
        ];
        $userAttributes = (new Attributes())->normalizeAttributesArray(
            [
                'intAttribute' => '7890',
                'boolAttribute1' => '1',
                'boolAttributeYes' => 'yes',
                'boolAttributeTrue' => 'true',
                'boolAttributeOther' => 'anythingElseIsFalse',
                'stringAttribute' => 'someString',
            ]
        );
        $claimTranslator = new ClaimTranslatorExtractor(self::$userIdAttr, [$claimSet], $translate);
        $releasedClaims = $claimTranslator->extract(
            ['typeConversion'],
            $userAttributes
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
            'urn:oid:2.5.4.3' => 'someString'
        ];

        $this->assertSame($expectedClaims, $releasedClaims);
    }

    /**
     * Test that the default translator configuration sets address correctly.
     */
    public function testDefaultTypeConversion(): void
    {
        // Address is the only non-string attribute with a default saml source
        $userAttributes = (new Attributes())->normalizeAttributesArray(
            [
                'postalAddress' => 'myAddress'
            ]
        );
        $claimTranslator = new ClaimTranslatorExtractor(self::$userIdAttr);
        $releasedClaims = $claimTranslator->extract(
            ['address'],
            $userAttributes
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
     */
    public function testStandardClaimTypesCanBeSet(): void
    {
        $translate = [
            'updated_at' => [
                'type' => 'int',
                'last_updated'
            ],
            'email_verified' => [
                'type' => 'bool',
                'is_email_verified'
            ],
            'phone_number_verified' => [
                'type' => 'bool',
                'is_phone_number_verified'
            ],
            'address' => [
                'type' => 'json',
                'claims' => [
                    'country' => ['country'],
                    'postal_code' => ['postal'],
                ]
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
            ]
        );
        $claimTranslator = new ClaimTranslatorExtractor(self::$userIdAttr, [], $translate);
        $releasedClaims = $claimTranslator->extract(
            ['address', 'profile', 'email', 'phone'],
            $userAttributes
        );
        $expectedClaims = [
            'address' => [
                'country' => 'CA',
                'postal_code' => '93105'
            ],
            'updated_at' => 12341,
            'email_verified' => true,
            'phone_number_verified' => false,
        ];

        $this->assertSame($expectedClaims, $releasedClaims);
    }

    public function testInvalidTypeConversion(): void
    {
        $this->expectExceptionMessage("Cannot convert '7890F' to int");
        $claimSet = new ClaimSetEntity('typeConversion', ['testClaim',]);
        $translate = [
            'testClaim' => [
                'type' => 'int',
                'testClaim'
            ],
        ];
        $userAttributes = (new Attributes())->normalizeAttributesArray(['testClaim' => '7890F',]);
        $claimTranslator = new ClaimTranslatorExtractor(self::$userIdAttr, [$claimSet], $translate);
        $claimTranslator->extract(['typeConversion'], $userAttributes);
    }

    public function testExtractRequestClaimsUserInfo(): void
    {
        $claimTranslator = new ClaimTranslatorExtractor(self::$userIdAttr);
        $requestClaims = [
            "userinfo" => [
                "name" => ['essential' => true]
            ]
        ];

        $claims = $claimTranslator->extractAdditionalUserInfoClaims($requestClaims, ['cn' => ['bob']]);
        $this->assertEquals(['name' => 'bob'], $claims);
    }

    public function testExtractRequestClaimsIdToken(): void
    {
        $claimTranslator = new ClaimTranslatorExtractor(self::$userIdAttr);
        $requestClaims = [
            "id_token" => [
                "name" => ['essential' => true]
            ]
        ];

        $claims = $claimTranslator->extractAdditionalIdTokenClaims($requestClaims, ['displayName' => ['bob']]);
        $this->assertEquals(['name' => 'bob'], $claims);
    }
}

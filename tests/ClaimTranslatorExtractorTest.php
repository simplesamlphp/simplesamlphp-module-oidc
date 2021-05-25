<?php

namespace Tests\SimpleSAML\Modules\OpenIDConnect;

use OpenIDConnectServer\Entities\ClaimSetEntity;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Modules\OpenIDConnect\ClaimTranslatorExtractor;
use SimpleSAML\Utils\Attributes;

class ClaimTranslatorExtractorTest extends TestCase
{

    /**
     * Test various type conversions work, including types in subobjects
     * @throws \OpenIDConnectServer\Exception\InvalidArgumentException
     */
    public function testTypeConversion(): void
    {
        $claimSet = new ClaimSetEntity('typeConversion', [
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
        ]);
        $translate = [
            'int:intClaim' => ['intAttribute'],
            'bool:boolClaim1' => ['boolAttribute1'],
            'bool:boolClaimYes' => ['boolAttributeYes'],
            'bool:boolClaimTrue' => ['boolAttributeTrue'],
            'bool:boolClaimOther' => ['boolAttributeOther'],
            'defaultClaim' => ['stringAttribute'],
            'string:stringClaim' => ['stringAttribute'],
            'jsonClaim' => [
                'int:subIntClaim' => ['intAttribute'],
                'bool:subBoolClaim' => ['boolAttribute1'],
                'string:subStringClaim' => ['stringAttribute'],
            ],
            'urn:oid:2.5.4.3' => ['stringAttribute']
        ];
        $userAttributes = Attributes::normalizeAttributesArray([
            'intAttribute' => '7890',
            'boolAttribute1' => '1',
            'boolAttributeYes' => 'yes',
            'boolAttributeTrue' => 'true',
            'boolAttributeOther' => 'anythingElseIsFalse',
            'stringAttribute' => 'someString',
        ]);
        $claimTranslator = new ClaimTranslatorExtractor([$claimSet], $translate);
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
        $userAttributes = Attributes::normalizeAttributesArray(
            [
                'postalAddress' => 'myAddress'
            ]
        );
        $claimTranslator = new ClaimTranslatorExtractor();
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
     * @throws \OpenIDConnectServer\Exception\InvalidArgumentException
     */
    public function testStandardClaimTypesCanBeSet(): void
    {
        $translate = [
            'int:updated_at' => ['last_updated'],
            'bool:email_verified' => ['is_email_verified'],
            'bool:phone_number_verified' => ['is_phone_number_verified'],
            'address' => [
                'country' => ['country'],
                'postal_code' => ['postal'],
            ],
        ];
        $userAttributes = Attributes::normalizeAttributesArray(
            [
                'country' => 'CA',
                'postal' => '93105',
                'postalAddress' => 'should not appear in mapping',
                'last_updated' => '12341',
                'is_email_verified' => 'yes',
                'is_phone_number_verified' => 'no',
            ]
        );
        $claimTranslator = new ClaimTranslatorExtractor([], $translate);
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
            'int:testClaim' => ['testClaim'],
        ];
        $userAttributes = Attributes::normalizeAttributesArray(['testClaim' => '7890F',]);
        $claimTranslator = new ClaimTranslatorExtractor([$claimSet], $translate);
        $claimTranslator->extract(['typeConversion'], $userAttributes);
    }
}

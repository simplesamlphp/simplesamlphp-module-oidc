<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\VerifiableCredentials\ClaimsDescriptionValidator;

/**
 * The claims descriptions of OpenID4VCI 1.0 Appendix B, held to the same rules wherever they come from. What the
 * reasons name is the caller's: the authorization details (AuthorizationDetailsRuleTest) and the credential
 * configurations (ModuleConfigTest) go through every reason with their own words.
 */
#[CoversClass(ClaimsDescriptionValidator::class)]
class ClaimsDescriptionValidatorTest extends TestCase
{
    protected const string OF = 'the thing under test';


    /**
     * Each reason names what the descriptions belong to, as the caller put it.
     */
    #[DataProvider('faultyClaimsDescriptionsProvider')]
    public function testNamesWhatTheFaultyDescriptionsBelongTo(mixed $claimsDescriptions, string $reason): void
    {
        $this->assertSame(
            $reason,
            (new ClaimsDescriptionValidator())->findFaultInClaimsDescriptions($claimsDescriptions, self::OF),
        );
    }


    public static function faultyClaimsDescriptionsProvider(): array
    {
        return [
            'not an array' => [
                'given_name',
                'The claims of ' . self::OF . ' are not a non-empty array of claims descriptions.',
            ],
            'not an object' => [['given_name'], 'A claims description of ' . self::OF . ' is not a JSON object.'],
            'no path' => [
                [['mandatory' => true]],
                'A claims description of ' . self::OF . ' has no path which is a claims path pointer: a ' .
                'non-empty array of strings, nulls and non-negative integers.',
            ],
            'a mandatory member which is not a boolean' => [
                [['path' => ['given_name'], 'mandatory' => 1]],
                'The mandatory member of a claims description of ' . self::OF . ' is not a boolean.',
            ],
            'a contradiction' => [
                [['path' => ['address', null]], ['path' => ['address', 'locality']]],
                'Two claims descriptions of ' . self::OF . ' contradict each other: one addresses an object member ' .
                'where another addresses an array, or all elements of an array where another addresses one of them.',
            ],
            'a repetition' => [
                [['path' => ['given_name']], ['path' => ['given_name']]],
                'Two claims descriptions of ' . self::OF . ' address the same claim.',
            ],
        ];
    }


    public function testFindsNoFaultInWellFormedDescriptions(): void
    {
        $this->assertNull((new ClaimsDescriptionValidator())->findFaultInClaimsDescriptions(
            [
                ['path' => ['given_name'], 'mandatory' => true, 'display' => [['name' => 'Given name']]],
                ['path' => ['address', 'locality']],
                ['path' => ['address', 'country']],
                ['path' => ['nationalities', null]],
                ['path' => ['degrees', 0, 'type']],
                ['path' => ['degrees', 1, 'type']],
            ],
            self::OF,
        ));
    }


    #[DataProvider('claimsPathPointerProvider')]
    public function testTellsAClaimsPathPointer(mixed $path, bool $isPointer): void
    {
        $this->assertSame($isPointer, (new ClaimsDescriptionValidator())->isClaimsPathPointer($path));
    }


    public static function claimsPathPointerProvider(): array
    {
        return [
            'members' => [['address', 'locality'], true],
            'every element and one' => [['degrees', null, 'type', 0], true],
            'empty' => [[], false],
            'not an array' => ['address.locality', false],
            'an object' => [['a' => 'address'], false],
            'a negative index' => [['degrees', -1], false],
            'a float' => [['degrees', 1.0], false],
            'a boolean' => [['degrees', true], false],
            'a nested array' => [[['address']], false],
        ];
    }


    /**
     * A JSON object decodes to an array with named members, or to an empty one; a JSON array to a list.
     */
    public function testTellsAJsonObjectFromAJsonArray(): void
    {
        $sut = new ClaimsDescriptionValidator();

        $this->assertTrue($sut->isJsonObject(['path' => ['a']]));
        $this->assertTrue($sut->isJsonObject([]));
        $this->assertFalse($sut->isJsonObject([['path' => ['a']]]));
        $this->assertFalse($sut->isJsonObject('path'));

        $this->assertTrue($sut->isNonEmptyJsonArray([['path' => ['a']]]));
        $this->assertFalse($sut->isNonEmptyJsonArray([]));
        $this->assertFalse($sut->isNonEmptyJsonArray(['path' => ['a']]));
        $this->assertFalse($sut->isNonEmptyJsonArray('path'));
    }
}

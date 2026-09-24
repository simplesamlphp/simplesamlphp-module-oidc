<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\ValueAbstracts\ForeignIssuerList;

#[CoversClass(ForeignIssuerList::class)]
class ForeignIssuerListTest extends TestCase
{
    public function testAnAllowListPermitsTheIssuersItNamesOnly(): void
    {
        $sut = ForeignIssuerList::allow(['https://node-a.example.org', 'https://node-b.example.org']);

        $this->assertTrue($sut->isAllowList());
        $this->assertSame(['https://node-a.example.org', 'https://node-b.example.org'], $sut->getIssuers());
        $this->assertTrue($sut->permits('https://node-a.example.org'));
        $this->assertTrue($sut->permits('https://node-b.example.org'));
        $this->assertFalse($sut->permits('https://node-c.example.org'));
    }


    public function testADenyListPermitsEveryIssuerButTheOnesItNames(): void
    {
        $sut = ForeignIssuerList::deny(['https://node-a.example.org']);

        $this->assertFalse($sut->isAllowList());
        $this->assertFalse($sut->permits('https://node-a.example.org'));
        $this->assertTrue($sut->permits('https://node-b.example.org'));
    }


    public function testAnEmptyAllowListPermitsNothingAndAnEmptyDenyListEverything(): void
    {
        $this->assertFalse(ForeignIssuerList::allow([])->permits('https://node-a.example.org'));
        $this->assertTrue(ForeignIssuerList::deny([])->permits('https://node-a.example.org'));
    }


    /**
     * Issuers are compared exactly: a trailing slash or a different case is another issuer.
     */
    public function testComparesIssuersExactly(): void
    {
        $sut = ForeignIssuerList::allow(['https://node-a.example.org']);

        $this->assertFalse($sut->permits('https://node-a.example.org/'));
        $this->assertFalse($sut->permits('https://NODE-A.example.org'));
    }


    public function testReadsNoListFromAClientRecordWithoutOne(): void
    {
        $this->assertNull(ForeignIssuerList::fromClientMetadata(null));
    }


    public function testReadsTheListAClientRecordKeeps(): void
    {
        $allow = ForeignIssuerList::fromClientMetadata(['allow' => ['https://node-a.example.org']]);
        $deny = ForeignIssuerList::fromClientMetadata(['deny' => []]);

        $this->assertInstanceOf(ForeignIssuerList::class, $allow);
        $this->assertTrue($allow->isAllowList());
        $this->assertSame(['https://node-a.example.org'], $allow->getIssuers());

        $this->assertInstanceOf(ForeignIssuerList::class, $deny);
        $this->assertFalse($deny->isAllowList());
        $this->assertSame([], $deny->getIssuers());
    }


    public static function unusableStoredValuesProvider(): array
    {
        return [
            'a string' => ['https://node-a.example.org'],
            'false' => [false],
            'an empty array' => [[]],
            'both lists' => [['allow' => [], 'deny' => []]],
            'another key' => [['permit' => ['https://node-a.example.org']]],
            'a bare list' => [['https://node-a.example.org']],
            'issuers which are not a list' => [['allow' => 'https://node-a.example.org']],
            'issuers keyed by name' => [['deny' => ['a' => 'https://node-a.example.org']]],
            'an issuer which is not a string' => [['allow' => [1]]],
            'an empty issuer' => [['allow' => ['']]],
        ];
    }


    /**
     * A stored value which can not be applied is refused, never read as "no list": that would lift a restriction
     * somebody put there.
     */
    #[DataProvider('unusableStoredValuesProvider')]
    public function testRefusesAStoredValueWhichIsNeitherShape(mixed $value): void
    {
        $this->expectException(OidcException::class);

        ForeignIssuerList::fromClientMetadata($value);
    }
}

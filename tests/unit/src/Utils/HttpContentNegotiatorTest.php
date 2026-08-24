<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Utils\HttpContentNegotiator;

#[CoversClass(HttpContentNegotiator::class)]
#[AllowMockObjectsWithoutExpectations]
class HttpContentNegotiatorTest extends TestCase
{
    protected const string MEDIA_TYPE = 'application/statuslist+jwt';


    protected function sut(): HttpContentNegotiator
    {
        return new HttpContentNegotiator();
    }


    /**
     * @return array<string,array{?string,bool}>
     */
    public static function acceptHeaders(): array
    {
        return [
            'absent' => [null, true],
            'empty' => ['', true],
            'wildcard' => ['*/*', true],
            'type wildcard' => ['application/*', true],
            'exact' => ['application/statuslist+jwt', true],
            'exact among others' => ['text/html, application/statuslist+jwt, */*', true],
            'unrelated type only' => ['text/html', false],
            'unrelated type wildcard' => ['text/*', false],
            'with a weight' => ['application/statuslist+jwt;q=0.5', true],
            'refused outright' => ['application/statuslist+jwt;q=0', false],
            'case insensitive' => ['APPLICATION/STATUSLIST+JWT', true],
            'untidy whitespace' => ["  text/html ,\tapplication/statuslist+jwt  ", true],
            'malformed element is skipped' => ['nonsense, application/statuslist+jwt', true],
            'malformed element alone' => ['nonsense', false],
            'parameters on the range are ignored' => ['application/statuslist+jwt;version=2', true],
        ];
    }


    #[DataProvider('acceptHeaders')]
    public function testAcceptsMediaType(?string $accept, bool $expected): void
    {
        $this->assertSame($expected, $this->sut()->acceptsMediaType($accept, self::MEDIA_TYPE));
    }


    /**
     * The specific range wins over the general one whichever way round the weights fall, which is what
     * lets a client say "anything but this" -- and, the other way round, "only this".
     */
    public function testTheMoreSpecificRangeDecidesRegardlessOfWeight(): void
    {
        $this->assertFalse(
            $this->sut()->acceptsMediaType('*/*;q=1, application/statuslist+jwt;q=0', self::MEDIA_TYPE),
        );

        $this->assertTrue(
            $this->sut()->acceptsMediaType('*/*;q=0, application/statuslist+jwt;q=1', self::MEDIA_TYPE),
        );

        // Between the two wildcards, the one naming the type is the more specific.
        $this->assertFalse(
            $this->sut()->acceptsMediaType('*/*;q=1, application/*;q=0', self::MEDIA_TYPE),
        );
    }


    /**
     * Everything past the weight is accept-ext rather than a second weight.
     */
    public function testIgnoresAcceptExtensionsAfterTheWeight(): void
    {
        $this->assertTrue(
            $this->sut()->acceptsMediaType('application/statuslist+jwt;q=1;ext=0', self::MEDIA_TYPE),
        );
    }


    public function testNoAcceptEncodingMeansNoEncoding(): void
    {
        $this->assertNull($this->sut()->preferredContentCoding(null, 'gzip'));
        $this->assertNull($this->sut()->preferredContentCoding('', 'gzip'));
    }


    public function testChoosesAnOfferedCoding(): void
    {
        $this->assertSame('gzip', $this->sut()->preferredContentCoding('gzip, deflate', 'gzip'));
        $this->assertSame('gzip', $this->sut()->preferredContentCoding('GZIP', 'gzip'));
    }


    public function testDeclinesACodingWhichIsNotOffered(): void
    {
        $this->assertNull($this->sut()->preferredContentCoding('br, zstd', 'gzip'));
    }


    public function testHonoursAWildcard(): void
    {
        $this->assertSame('gzip', $this->sut()->preferredContentCoding('*', 'gzip'));
    }


    /**
     * A weight of zero is a refusal, and an explicit refusal beats a permissive wildcard.
     */
    public function testARefusedCodingIsNotUsed(): void
    {
        $this->assertNull($this->sut()->preferredContentCoding('gzip;q=0', 'gzip'));
        $this->assertNull($this->sut()->preferredContentCoding('*, gzip;q=0', 'gzip'));
    }


    public function testPrefersTheHigherWeightedOfSeveralOfferedCodings(): void
    {
        $this->assertSame(
            'deflate',
            $this->sut()->preferredContentCoding('gzip;q=0.2, deflate;q=0.9', 'gzip', 'deflate'),
        );
    }


    /**
     * Where the client has no preference between two codings, the order they are offered in decides.
     */
    public function testTiesGoToTheFirstOfferedCoding(): void
    {
        $this->assertSame(
            'gzip',
            $this->sut()->preferredContentCoding('deflate, gzip', 'gzip', 'deflate'),
        );
    }
}

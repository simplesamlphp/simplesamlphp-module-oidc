<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Helpers;

use DateInterval;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Helpers\DateTime;

#[CoversClass(DateTime::class)]
#[AllowMockObjectsWithoutExpectations]
class DateTimeTest extends TestCase
{
    protected function sut(): DateTime
    {
        return new DateTime();
    }


    public function testCanGetUtc(): void
    {
        $this->assertInstanceOf(DateTimeImmutable::class, $this->sut()->getUtc());
        $this->assertSame(
            'UTC',
            $this->sut()->getUtc()->getTimezone()->getName(),
        );
    }


    public function testCanGetFromTimestamp(): void
    {
        $timestamp = (new DateTimeImmutable())->getTimestamp();

        $this->assertSame(
            $timestamp,
            $this->sut()->getFromTimestamp($timestamp)->getTimestamp(),
        );
    }


    public function testCanGetSecondsToExpirationTime(): void
    {
        $expirationTime = (new DateTimeImmutable())->getTimestamp() + 60;

        $this->assertSame(
            60,
            $this->sut()->getSecondsToExpirationTime($expirationTime),
        );
    }


    /**
     * The boundaries are counted from the epoch, so they fall on UTC midnight and UTC hours whatever the
     * moment's timezone, and the moment keeps its timezone.
     */
    #[DataProvider('roundingProvider')]
    public function testRoundsToUtcBoundariesKeepingTheTimezone(
        string $granularity,
        string $roundedDown,
        string $roundedUp,
    ): void {
        $moment = new DateTimeImmutable('2026-10-02T14:37:21.5+02:00');

        $interval = new DateInterval($granularity);

        $this->assertSame($roundedDown, $this->sut()->floorTo($moment, $interval)->format('c'));
        $this->assertSame($roundedUp, $this->sut()->ceilTo($moment, $interval)->format('c'));
    }


    /**
     * @return array<string,array{0: string, 1: string, 2: string}>
     */
    public static function roundingProvider(): array
    {
        return [
            'a day' => ['P1D', '2026-10-02T02:00:00+02:00', '2026-10-03T02:00:00+02:00'],
            'an hour' => ['PT1H', '2026-10-02T14:00:00+02:00', '2026-10-02T15:00:00+02:00'],
            // Counted from the epoch, not from the hour: 12:00 and 13:30 UTC are multiples of ninety minutes.
            'ninety minutes' => ['PT90M', '2026-10-02T14:00:00+02:00', '2026-10-02T15:30:00+02:00'],
            // The epoch began on a Thursday, so a week does too.
            'a week' => ['P1W', '2026-10-01T02:00:00+02:00', '2026-10-08T02:00:00+02:00'],
        ];
    }


    public function testAMomentOnABoundaryStaysOnIt(): void
    {
        $moment = new DateTimeImmutable('2026-10-02T00:00:00+00:00');
        $day = new DateInterval('P1D');

        $this->assertSame('2026-10-02T00:00:00+00:00', $this->sut()->floorTo($moment, $day)->format('c'));
        $this->assertSame('2026-10-02T00:00:00+00:00', $this->sut()->ceilTo($moment, $day)->format('c'));
    }


    /**
     * A JWT time claim has no fraction of a second, but the moment rounded may: one half a second past a
     * boundary is rounded down onto it and up to the next, so that rounding up never lands before the
     * moment, at whatever granularity.
     */
    #[DataProvider('fractionPastABoundaryProvider')]
    public function testAFractionOfASecondPastABoundaryRoundsUpToTheNext(
        string $granularity,
        string $roundedDown,
        string $roundedUp,
    ): void {
        $moment = new DateTimeImmutable('2026-10-02T00:00:00.5+00:00');
        $interval = new DateInterval($granularity);

        $this->assertSame($roundedDown, $this->sut()->floorTo($moment, $interval)->format('Y-m-d\TH:i:s.uP'));
        $this->assertSame($roundedUp, $this->sut()->ceilTo($moment, $interval)->format('Y-m-d\TH:i:s.uP'));
    }


    /**
     * @return array<string,array{0: string, 1: string, 2: string}>
     */
    public static function fractionPastABoundaryProvider(): array
    {
        return [
            'a second' => ['PT1S', '2026-10-02T00:00:00.000000+00:00', '2026-10-02T00:00:01.000000+00:00'],
            'a day' => ['P1D', '2026-10-02T00:00:00.000000+00:00', '2026-10-03T00:00:00.000000+00:00'],
        ];
    }


    /**
     * The remainder is counted forward from the boundary below even for a moment before the epoch, where
     * `%` alone would count it towards zero and round the wrong way.
     */
    public function testRoundsAMomentBeforeTheEpoch(): void
    {
        $moment = new DateTimeImmutable('1969-12-31T23:30:00+00:00');
        $hour = new DateInterval('PT1H');

        $this->assertSame('1969-12-31T23:00:00+00:00', $this->sut()->floorTo($moment, $hour)->format('c'));
        $this->assertSame('1970-01-01T00:00:00+00:00', $this->sut()->ceilTo($moment, $hour)->format('c'));
    }


    public function testNoTimeAtAllLeavesTheMomentAsItIs(): void
    {
        $moment = new DateTimeImmutable('2026-10-02T14:37:21.5+02:00');

        $this->assertSame($moment, $this->sut()->floorTo($moment, new DateInterval('PT0S')));
        $this->assertSame($moment, $this->sut()->ceilTo($moment, new DateInterval('PT0S')));
    }


    #[DataProvider('granularityWithoutFixedLengthProvider')]
    public function testRefusesAGranularityWithoutAFixedLength(string $granularity): void
    {
        $moment = new DateTimeImmutable('2026-10-02T14:37:21+02:00');

        $this->expectException(InvalidArgumentException::class);

        $this->sut()->floorTo($moment, new DateInterval($granularity));
    }


    /**
     * @return array<string,array{0: string}>
     */
    public static function granularityWithoutFixedLengthProvider(): array
    {
        return [
            'a month' => ['P1M'],
            'a year' => ['P1Y'],
        ];
    }
}

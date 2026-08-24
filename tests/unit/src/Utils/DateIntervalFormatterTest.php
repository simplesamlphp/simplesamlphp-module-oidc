<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;

#[CoversClass(DateIntervalFormatter::class)]
#[AllowMockObjectsWithoutExpectations]
class DateIntervalFormatterTest extends TestCase
{
    protected function sut(): DateIntervalFormatter
    {
        return new DateIntervalFormatter();
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(DateIntervalFormatter::class, $this->sut());
    }


    public static function humanReadableProvider(): array
    {
        return [
            'minutes' => ['PT10M', '10 minutes'],
            'single minute' => ['PT1M', '1 minute'],
            'hour' => ['PT1H', '1 hour'],
            'month' => ['P1M', '1 month'],
            // Years must not be dropped, which is what the previous template format string did.
            'year' => ['P1Y', '1 year'],
            'combined' => ['P1Y2M3DT4H5M6S', '1 year 2 months 3 days 4 hours 5 minutes 6 seconds'],
            'zero' => ['PT0S', '0 seconds'],
            // DateInterval does not normalize, so components are reported as configured.
            'not normalized' => ['PT48H', '48 hours'],
        ];
    }


    #[DataProvider('humanReadableProvider')]
    public function testCanRenderHumanReadable(string $durationSpec, string $expected): void
    {
        $this->assertSame($expected, $this->sut()->toHumanReadable(new DateInterval($durationSpec)));
    }


    public static function durationSpecProvider(): array
    {
        return [
            'minutes' => ['PT10M'],
            'hour' => ['PT1H'],
            'month' => ['P1M'],
            'year' => ['P1Y'],
            'day' => ['P1D'],
            'combined' => ['P1Y2M3DT4H5M6S'],
            'zero' => ['PT0S'],
            'not normalized' => ['PT48H'],
        ];
    }


    #[DataProvider('durationSpecProvider')]
    public function testCanRenderBackToDurationSpec(string $durationSpec): void
    {
        $this->assertSame($durationSpec, $this->sut()->toDurationSpec(new DateInterval($durationSpec)));
    }
}

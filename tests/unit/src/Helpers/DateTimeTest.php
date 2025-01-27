<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Helpers;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Helpers\DateTime;

#[CoversClass(DateTime::class)]
class DateTimeTest extends TestCase
{
    protected function sut(): DateTime
    {
        return new DateTime();
    }

    public function testCanGetUtc(): void
    {
        $this->assertInstanceOf(\DateTimeImmutable::class, $this->sut()->getUtc());
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
}

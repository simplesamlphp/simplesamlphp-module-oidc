<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils\Debug;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\InvalidArgumentException;
use Psr\Log\LogLevel;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Utils\Debug\ArrayLogger;

#[CoversClass(ArrayLogger::class)]
class ArrayLoggerTest extends TestCase
{
    protected MockObject $helpersMock;
    protected MockObject $dateTimeMock;
    protected int $weight;

    protected function setUp(): void
    {
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->dateTimeMock = $this->createMock(Helpers\DateTime::class);
        $this->helpersMock->method('dateTime')->willReturn($this->dateTimeMock);
        $this->dateTimeMock->method('getUtc')->willReturn(new \DateTimeImmutable());
        $this->weight = ArrayLogger::WEIGHT_DEBUG;
    }

    protected function sut(
        ?Helpers $helpers = null,
        ?int $weight = null,
    ): ArrayLogger {
        $helpers ??= $this->helpersMock;
        $weight ??= $this->weight;

        return new ArrayLogger($helpers, $weight);
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(ArrayLogger::class, $this->sut());
    }

    public function testCanLogEntriesBasedOnWeight(): void
    {
        $sut = $this->sut();
        $this->assertEmpty($sut->getEntries());

        $sut->debug('debug message');
        $sut->info('info message');
        $sut->notice('notice message');
        $sut->warning('warning message');
        $sut->error('error message');
        $sut->critical('critical message');
        $sut->alert('alert message');
        $sut->emergency('emergency message');
        $sut->log(LogLevel::DEBUG, 'debug message');

        $this->assertCount(9, $sut->getEntries());
    }

    public function testWontLogLessThanEmergency(): void
    {
        $sut = $this->sut(weight: ArrayLogger::WEIGHT_EMERGENCY);

        $sut->debug('debug message');
        $sut->info('info message');
        $sut->notice('notice message');
        $sut->warning('warning message');
        $sut->error('error message');
        $sut->critical('critical message');
        $sut->alert('alert message');

        $this->assertEmpty($sut->getEntries());

        $sut->emergency('emergency message');
        $this->assertNotEmpty($sut->getEntries());
    }

    public function testThrowsOnInvalidLogLevel(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->sut()->log('invalid', 'message');
    }
}

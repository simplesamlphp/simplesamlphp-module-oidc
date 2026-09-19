<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\InvalidArgumentException;
use Psr\Log\LogLevel;
use ReflectionProperty;
use SimpleSAML\Logger;
use SimpleSAML\Logger\LoggingHandlerInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use Stringable;

/**
 * The PSR-3 logger the module's services log through, over SimpleSAMLphp's static `Logger`.
 *
 * Each of the eight level methods calls the `Logger` method of the same level with the message and, when
 * there is a context, a space and the context as `var_export()` writes it; `log()` dispatches on the
 * PSR-3 level names and refuses any other. The tests stand a logging handler in for SimpleSAMLphp's own
 * -- the seam `Logger::setLoggingHandler()` offers -- and open the level up to debug, so every line
 * reaches the handler with its SimpleSAMLphp level and the line as the logger formats it, which ends with
 * the message. Both are put back afterwards.
 */
#[CoversClass(LoggerService::class)]
#[AllowMockObjectsWithoutExpectations]
class LoggerServiceTest extends TestCase
{
    protected const string MESSAGE = 'Something happened.';

    protected const array CONTEXT = ['clientId' => 'client-a1b2c3', 'attempt' => 2];

    protected const string CONTEXT_AS_WRITTEN = "array (\n  'clientId' => 'client-a1b2c3',\n  'attempt' => 2,\n)";


    protected MockObject $loggingHandlerMock;


    protected function setUp(): void
    {
        $this->loggingHandlerMock = $this->createMock(LoggingHandlerInterface::class);
        Logger::setLoggingHandler($this->loggingHandlerMock);
        Logger::setLogLevel(Logger::DEBUG);
    }


    protected function tearDown(): void
    {
        Logger::setLoggingHandler(null);
        (new ReflectionProperty(Logger::class, 'logLevel'))->setValue(null, null);
        Logger::setTrackId(Logger::NO_TRACKID);
    }


    protected function sut(): LoggerService
    {
        return new LoggerService();
    }


    protected function expectOneLine(int $level, string $message): void
    {
        $this->loggingHandlerMock->expects($this->once())
            ->method('log')
            ->with($level, $this->stringEndsWith('] ' . $message));
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(LoggerService::class, $this->sut());
    }


    /**
     * Not a singleton, whatever the name: each call is a new instance.
     */
    public function testGetInstanceIsANewInstanceEachTime(): void
    {
        $this->assertInstanceOf(LoggerService::class, LoggerService::getInstance());
        $this->assertNotSame(LoggerService::getInstance(), LoggerService::getInstance());
    }


    #[DataProvider('levelProvider')]
    public function testLogsAtTheLevelOfTheMethod(string $method, int $level): void
    {
        $this->expectOneLine($level, self::MESSAGE);

        $this->sut()->$method(self::MESSAGE);
    }


    #[DataProvider('levelProvider')]
    public function testLogsAtTheLevelNamedToLog(string $method, int $level): void
    {
        $this->expectOneLine($level, self::MESSAGE);

        $this->sut()->log($method, self::MESSAGE);
    }


    /**
     * The PSR-3 method names are the PSR-3 level names, so one list serves both.
     *
     * @return array<string,array{string,int}>
     */
    public static function levelProvider(): array
    {
        return [
            'emergency' => [LogLevel::EMERGENCY, Logger::EMERG],
            'alert' => [LogLevel::ALERT, Logger::ALERT],
            'critical' => [LogLevel::CRITICAL, Logger::CRIT],
            'error' => [LogLevel::ERROR, Logger::ERR],
            'warning' => [LogLevel::WARNING, Logger::WARNING],
            'notice' => [LogLevel::NOTICE, Logger::NOTICE],
            'info' => [LogLevel::INFO, Logger::INFO],
            'debug' => [LogLevel::DEBUG, Logger::DEBUG],
        ];
    }


    public function testAppendsTheContextAsVarExportWritesIt(): void
    {
        $this->expectOneLine(Logger::WARNING, self::MESSAGE . ' ' . self::CONTEXT_AS_WRITTEN);

        $this->sut()->warning(self::MESSAGE, self::CONTEXT);
    }


    public function testAppendsTheContextThroughLogAsWell(): void
    {
        $this->expectOneLine(Logger::INFO, self::MESSAGE . ' ' . self::CONTEXT_AS_WRITTEN);

        $this->sut()->log(LogLevel::INFO, self::MESSAGE, self::CONTEXT);
    }


    public function testAppendsNothingForAnEmptyContext(): void
    {
        $this->expectOneLine(Logger::ERR, self::MESSAGE);

        $this->sut()->error(self::MESSAGE, []);
    }


    public function testWritesAStringableMessageAsItsString(): void
    {
        $message = new class implements Stringable {
            public function __toString(): string
            {
                return 'Something stringable happened.';
            }
        };
        $this->expectOneLine(Logger::NOTICE, 'Something stringable happened.');

        $this->sut()->notice($message);
    }


    /**
     * Refused with PSR-3's own exception, and nothing is logged. The message ends with a doubled quote,
     * pinned as spelled.
     */
    public function testRefusesALevelWhichIsNotAPsr3One(): void
    {
        $this->loggingHandlerMock->expects($this->never())->method('log');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Unrecognized log level 'verbose''");

        $this->sut()->log('verbose', self::MESSAGE);
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use JsonSerializable;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\InvalidArgumentException;
use Psr\Log\LogLevel;
use ReflectionProperty;
use RuntimeException;
use SimpleSAML\Logger;
use SimpleSAML\Logger\LoggingHandlerInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use Stringable;

/**
 * The PSR-3 logger the module's services log through, over SimpleSAMLphp's static `Logger`.
 *
 * Each of the eight level methods calls the `Logger` method of the same level with the message and, when
 * there is a context, a space and the context as JSON, all of it kept to one line; `log()` dispatches on the
 * PSR-3 level names and refuses any other. The tests stand a logging handler in for SimpleSAMLphp's own
 * -- the seam `Logger::setLoggingHandler()` offers -- and open the level up to debug, so every line
 * reaches the handler with its SimpleSAMLphp level and the line as the logger formats it, which ends with
 * what was logged. Both are put back afterwards.
 */
#[CoversClass(LoggerService::class)]
#[AllowMockObjectsWithoutExpectations]
class LoggerServiceTest extends TestCase
{
    protected const string MESSAGE = 'Something happened.';

    protected const array CONTEXT = ['clientId' => 'client-a1b2c3', 'attempt' => 2];

    protected const string CONTEXT_AS_WRITTEN = '{"clientId":"client-a1b2c3","attempt":2}';


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


    public function testAppendsTheContextAsJson(): void
    {
        $this->expectOneLine(Logger::WARNING, self::MESSAGE . ' ' . self::CONTEXT_AS_WRITTEN);

        $this->sut()->warning(self::MESSAGE, self::CONTEXT);
    }


    #[DataProvider('levelProvider')]
    public function testAppendsTheContextThroughLogAtEveryLevel(string $method, int $level): void
    {
        $this->expectOneLine($level, self::MESSAGE . ' ' . self::CONTEXT_AS_WRITTEN);

        $this->sut()->log($method, self::MESSAGE, self::CONTEXT);
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


    #[DataProvider('disallowedCharacterProvider')]
    public function testKeepsAMessageToOneLine(string $character): void
    {
        $line = $this->lineWrittenBy(
            fn(LoggerService $logger) => $logger->warning('before' . $character . 'after'),
        );

        $this->assertOneLine($line, $character);
        $this->assertStringEndsWith('] before after', $line);
    }


    /**
     * In a value, a key and a value further in, as a query string sent to the OP can have all three. A character
     * JSON escapes stays there as its escape, and any other gives way to a space.
     */
    #[DataProvider('disallowedCharacterProvider')]
    public function testKeepsAContextToOneLine(string $character): void
    {
        $sent = 'before' . $character . 'after';

        $line = $this->lineWrittenBy(
            fn(LoggerService $logger) => $logger->warning(self::MESSAGE, [
                'value' => $sent,
                $sent => 'key',
                'nested' => ['list' => [$sent]],
            ]),
        );

        $this->assertOneLine($line, $character);
        $this->assertSame(
            3,
            preg_match_all('/before(?: |(?:\\\\[a-z]|\\\\u[0-9a-f]{4})+)after/', $line),
            'Each of the three places should still hold the text around the character: ' . $line,
        );
    }


    /**
     * @return array<string,array{string}>
     */
    public static function disallowedCharacterProvider(): array
    {
        return [
            'line feed' => ["\n"],
            'carriage return' => ["\r"],
            'carriage return and line feed' => ["\r\n"],
            'vertical tab' => ["\x0B"],
            'form feed' => ["\x0C"],
            'tab' => ["\t"],
            'NUL' => ["\0"],
            'escape, as ANSI sequences start with' => ["\x1B"],
            'delete' => ["\x7F"],
            'next line, U+0085' => ["\u{0085}"],
            'line separator, U+2028' => ["\u{2028}"],
            'paragraph separator, U+2029' => ["\u{2029}"],
            'right-to-left override, U+202E' => ["\u{202E}"],
            'right-to-left isolate, U+2067' => ["\u{2067}"],
        ];
    }


    #[DataProvider('levelProvider')]
    public function testKeepsALineToOneAtEveryLevel(string $method, int $level): void
    {
        $this->expectOneLine($level, 'before after {"value":"before after"}');

        $this->sut()->$method("before\nafter", ['value' => "before\u{0085}after"]);
    }


    public function testARunOfDisallowedCharactersGivesWayToOneSpace(): void
    {
        $line = $this->lineWrittenBy(
            fn(LoggerService $logger) => $logger->warning("before\r\n\r\n\u{2028}\t\x1Bafter"),
        );

        $this->assertStringEndsWith('] before after', $line);
    }


    /**
     * A character JSON has an escape for stays in the value, so whoever reads the log can tell what was sent.
     */
    #[DataProvider('characterJsonEscapesProvider')]
    public function testAValueHoldingACharacterJsonEscapesCanStillBeReadBack(string $character): void
    {
        $sent = 'before' . $character . 'NOTICE [forged00] after';

        $line = $this->lineWrittenBy(fn(LoggerService $logger) => $logger->warning(self::MESSAGE, ['value' => $sent]));

        $this->assertOneLine($line, $character);
        $this->assertSame(
            ['value' => $sent],
            json_decode(substr($line, (int)strpos($line, '{"value"')), true, 512, JSON_THROW_ON_ERROR),
        );
    }


    /**
     * @return array<string,array{string}>
     */
    public static function characterJsonEscapesProvider(): array
    {
        return [
            'line feed' => ["\n"],
            'carriage return' => ["\r"],
            'carriage return and line feed' => ["\r\n"],
            'vertical tab' => ["\x0B"],
            'form feed' => ["\x0C"],
            'tab' => ["\t"],
            'NUL' => ["\0"],
            'escape, as ANSI sequences start with' => ["\x1B"],
            'line separator, U+2028' => ["\u{2028}"],
            'paragraph separator, U+2029' => ["\u{2029}"],
        ];
    }


    /**
     * What is not a disallowed character stays as it was: other alphabets in the message and in the context, and
     * a URI in the context without its slashes escaped.
     */
    public function testLeavesOtherTextAsItIs(): void
    {
        $line = $this->lineWrittenBy(
            fn(LoggerService $logger) => $logger->notice('Ivančić, 日本語, 100% "quoted".', [
                'name' => 'Ivančić',
                'redirect_uri' => 'https://rp.example/cb?a=b',
            ]),
        );

        $this->assertStringEndsWith(
            '] Ivančić, 日本語, 100% "quoted". {"name":"Ivančić","redirect_uri":"https://rp.example/cb?a=b"}',
            $line,
        );
    }


    /**
     * A request can send any bytes. The pattern which reads UTF-8 can not read these, and they must not get a
     * disallowed character past it, a multi-byte one included, or cost the line altogether.
     */
    #[DataProvider('disallowedCharacterProvider')]
    public function testKeepsAMessageWhichIsNotUtf8ToOneLine(string $character): void
    {
        $line = $this->lineWrittenBy(
            fn(LoggerService $logger) => $logger->warning("before\xFE" . $character . 'after', ['value' => 'kept']),
        );

        $this->assertOneLine($line, $character);
        $this->assertOneLine($line, "\xFE");
        $this->assertStringEndsWith('] before after {"value":"kept"}', $line);
    }


    public function testKeepsAContextWhichIsNotUtf8ToOneLine(): void
    {
        $line = $this->lineWrittenBy(
            fn(LoggerService $logger) => $logger->warning(self::MESSAGE, ['value' => "before\xFF\nafter", 'next' => 1]),
        );

        $this->assertOneLine($line, "\n");
        $this->assertOneLine($line, "\xFF");
        $this->assertStringEndsWith(self::MESSAGE . " {\"value\":\"before\u{FFFD}\\nafter\",\"next\":1}", $line);
    }


    /**
     * As AuthCodeGrant logs the results of its rules: JSON would write such an object as `{}`, losing its value, so it
     * is there as var_export() writes it, in a value of the JSON and further in, and a line break it holds stays
     * escaped.
     */
    public function testWritesAnObjectInAContextAsVarExportWritesIt(): void
    {
        $line = $this->lineWrittenBy(
            fn(LoggerService $logger) => $logger->debug(self::MESSAGE, [
                'object' => new Result('some-rule', 'protected value'),
                'nested' => ['list' => [new Result('other-rule', "line\nbreak")]],
                'enum' => ClientAuthenticationMethodsEnum::None,
            ]),
        );

        $this->assertOneLine($line, "\n");
        $this->assertSame(2, substr_count($line, 'RequestRules\\\\Result::__set_state'));
        $this->assertStringContainsString("'value' => 'protected value'", $line);
        $this->assertStringContainsString("'value' => 'line\\nbreak'", $line);
        $this->assertStringContainsString('ClientAuthenticationMethodsEnum::None', $line);
    }


    /**
     * No code of an object in the context runs for the log line, so none of it can cost the caller its request.
     */
    public function testDoesNotRunJsonSerializationOfAnObjectInAContext(): void
    {
        $object = new class implements JsonSerializable {
            public function jsonSerialize(): never
            {
                throw new RuntimeException('Not for a log line.');
            }
        };

        $line = $this->lineWrittenBy(
            fn(LoggerService $logger) => $logger->warning(self::MESSAGE, ['fine' => 'kept', 'object' => $object]),
        );

        $this->assertOneLine($line, "\n");
        $this->assertStringContainsString(self::MESSAGE . ' {"fine":"kept","object":"', $line);
    }


    /**
     * The entry is worth more than one value in its context: the line is written, and the values JSON can encode
     * are in it.
     */
    #[DataProvider('contextJsonCanNotEncodeProvider')]
    public function testStillWritesAContextJsonCanNotEncode(mixed $value): void
    {
        $line = $this->lineWrittenBy(
            fn(LoggerService $logger) => $logger->warning(self::MESSAGE, ['fine' => 'kept', 'other' => $value]),
        );

        $this->assertOneLine($line, "\n");
        $this->assertStringContainsString(self::MESSAGE . ' {"fine":"kept","other":', $line);
    }


    /**
     * @return array<string,array{mixed}>
     */
    public static function contextJsonCanNotEncodeProvider(): array
    {
        return [
            'infinity' => [INF],
            'not a number' => [NAN],
            'a resource' => [fopen('php://memory', 'r')],
        ];
    }


    /**
     * The same past the depth JSON allows, built here because PHPUnit can not export such a value from a provider.
     */
    public function testStillWritesAContextNestedPastTheDepthJsonAllows(): void
    {
        $tooDeep = 'bottom';
        for ($depth = 0; $depth < 600; $depth++) {
            $tooDeep = [$tooDeep];
        }

        $line = $this->lineWrittenBy(
            fn(LoggerService $logger) => $logger->warning(self::MESSAGE, ['fine' => 'kept', 'other' => $tooDeep]),
        );

        $this->assertOneLine($line, "\n");
        $this->assertStringContainsString(self::MESSAGE . ' {"fine":"kept","other":', $line);
    }


    /**
     * The line as the logging handler got it, the one line the callback made the logger write.
     *
     * @param callable(\SimpleSAML\Module\oidc\Services\LoggerService): void $logging
     */
    protected function lineWrittenBy(callable $logging): string
    {
        $written = [];
        $this->loggingHandlerMock->method('log')->willReturnCallback(
            static function (int $level, string $line) use (&$written): void {
                $written[] = $line;
            },
        );

        $logging($this->sut());

        $this->assertCount(1, $written);

        return $written[0];
    }


    /**
     * Not by the class's own patterns: \R is what PCRE takes for a line break whichever way it is spelled, and the
     * character sent is looked for as it was sent. A line which is not valid UTF-8 fails too, as bytes which can not be
     * read could hide a line break from whoever reads them next, this assertion included.
     */
    protected function assertOneLine(string $line, string $character): void
    {
        $lines = preg_split('/\R/u', $line);
        $this->assertIsArray($lines, 'Not valid UTF-8: ' . bin2hex($line));
        $this->assertCount(1, $lines, 'More than one line: ' . bin2hex($line));
        $this->assertStringNotContainsString($character, $line);
        $this->assertDoesNotMatchRegularExpression('/[\x00-\x1F\x7F]/', $line);
    }
}

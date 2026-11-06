<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use Psr\Log\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use SimpleSAML\Logger;
use Stringable;

class LoggerService implements LoggerInterface
{
    /**
     * What a line of the log may not hold: control characters, among them the C0 line breaks and U+0085, format
     * characters, among them the bidirectional overrides which make text read in another order, and the line and
     * paragraph separators. A run of them gives way to one space.
     */
    protected const string NOT_IN_A_LOG_LINE = '/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/u';

    /**
     * The same for a line which is not valid UTF-8, which the pattern above can not read: only printable ASCII stays.
     */
    protected const string NOT_IN_A_LOG_LINE_WHICH_IS_NOT_UTF8 = '/[^\x20-\x7E]+/';

    /**
     * Text stays readable, and a context which can not be encoded in full is written as far as it can be: a value of
     * another kind should not cost the whole log entry.
     */
    protected const int CONTEXT_ENCODING = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE |
    JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR;


    public function emergency(string|Stringable $message, array $context = []): void
    {
        Logger::emergency($this->asOneLine($message, $context));
    }


    public function alert(string|Stringable $message, array $context = []): void
    {
        Logger::alert($this->asOneLine($message, $context));
    }


    public function critical(string|Stringable $message, array $context = []): void
    {
        Logger::critical($this->asOneLine($message, $context));
    }


    public function error(string|Stringable $message, array $context = []): void
    {
        Logger::error($this->asOneLine($message, $context));
    }


    public function warning(string|Stringable $message, array $context = []): void
    {
        Logger::warning($this->asOneLine($message, $context));
    }


    public function notice(string|Stringable $message, array $context = []): void
    {
        Logger::notice($this->asOneLine($message, $context));
    }


    public function info(string|Stringable $message, array $context = []): void
    {
        Logger::info($this->asOneLine($message, $context));
    }


    public function debug(string|Stringable $message, array $context = []): void
    {
        Logger::debug($this->asOneLine($message, $context));
    }


    public function log(mixed $level, string|Stringable $message, array $context = []): void
    {
        match ($level) {
            LogLevel::ALERT => $this->alert($message, $context),
            LogLevel::CRITICAL => $this->critical($message, $context),
            LogLevel::DEBUG => $this->debug($message, $context),
            LogLevel::EMERGENCY => $this->emergency($message, $context),
            LogLevel::ERROR => $this->error($message, $context),
            LogLevel::INFO => $this->info($message, $context),
            LogLevel::NOTICE => $this->notice($message, $context),
            LogLevel::WARNING => $this->warning($message, $context),
            default => throw new InvalidArgumentException("Unrecognized log level '$level''"),
        };
    }


    public static function getInstance(): self
    {
        return new self();
    }


    /**
     * A message and its context as the one line they are written on. Both often hold what a request sent, whether or
     * not the request goes on to be accepted, and SimpleSAMLphp's logger writes what it is given, so a line break in
     * such a value would let the sender add lines of their own to the log. The context is JSON, which writes C0
     * control characters, U+2028 and U+2029 as escapes, so a value holding those can still be read, and what is left
     * of the disallowed characters gives way to a space.
     *
     * An object in the context is written as var_export() writes it, as text in the JSON: with its private properties
     * and without running any of its code, where JSON would show its public properties only, or whatever its
     * jsonSerialize() answers or throws.
     */
    protected function asOneLine(string|Stringable $message, array $context): string
    {
        $line = (string)$message;

        if ($context !== []) {
            array_walk_recursive($context, static function (mixed &$value): void {
                if (is_object($value)) {
                    $value = var_export($value, true);
                }
            });

            $line .= ' ' . (string)json_encode($context, self::CONTEXT_ENCODING);
        }

        return preg_replace(self::NOT_IN_A_LOG_LINE, ' ', $line) ??
        (string)preg_replace(self::NOT_IN_A_LOG_LINE_WHICH_IS_NOT_UTF8, ' ', $line);
    }
}

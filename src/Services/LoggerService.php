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
    public function emergency(string|Stringable $message, array $context = []): void
    {
        Logger::emergency((string)$message . ($context ? " " . var_export($context, true) : ""));
    }

    public function alert(string|Stringable $message, array $context = []): void
    {
        Logger::alert((string)$message . ($context ? " " . var_export($context, true) : ""));
    }

    public function critical(string|Stringable $message, array $context = []): void
    {
        Logger::critical((string)$message . ($context ? " " . var_export($context, true) : ""));
    }

    public function error(string|Stringable $message, array $context = []): void
    {
        Logger::error((string)$message . ($context ? " " . var_export($context, true) : ""));
    }

    public function warning(string|Stringable $message, array $context = []): void
    {
        Logger::warning((string)$message . ($context ? " " . var_export($context, true) : ""));
    }

    public function notice(string|Stringable $message, array $context = []): void
    {
        Logger::notice((string)$message . ($context ? " " . var_export($context, true) : ""));
    }

    public function info(string|Stringable $message, array $context = []): void
    {
        Logger::info((string)$message . ($context ? " " . var_export($context, true) : ""));
    }

    public function debug(string|Stringable $message, array $context = []): void
    {
        Logger::debug((string)$message . ($context ? " " . var_export($context, true) : ""));
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
}

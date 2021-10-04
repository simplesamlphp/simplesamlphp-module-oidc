<?php

namespace SimpleSAML\Module\oidc\Services;

use Psr\Log\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use SimpleSAML\Logger;

class LoggerService implements LoggerInterface
{
    public function emergency($message, array $context = []): void
    {
        Logger::emergency($message . ($context ? " " . var_export($context, true) : ""));
    }

    public function alert($message, array $context = []): void
    {
        Logger::alert($message . ($context ? " " . var_export($context, true) : ""));
    }

    public function critical($message, array $context = []): void
    {
        Logger::critical($message . ($context ? " " . var_export($context, true) : ""));
    }

    public function error($message, array $context = []): void
    {
        Logger::error($message . ($context ? " " . var_export($context, true) : ""));
    }

    public function warning($message, array $context = []): void
    {
        Logger::warning($message . ($context ? " " . var_export($context, true) : ""));
    }

    public function notice($message, array $context = []): void
    {
        Logger::notice($message . ($context ? " " . var_export($context, true) : ""));
    }

    public function info($message, array $context = []): void
    {
        Logger::info($message . ($context ? " " . var_export($context, true) : ""));
    }

    public function debug($message, array $context = []): void
    {
        Logger::debug($message . ($context ? " " . var_export($context, true) : ""));
    }

    public function log($level, $message, array $context = []): void
    {
        switch ($level) {
            case LogLevel::ALERT:
                $this->alert($message, $context);
                break;
            case LogLevel::CRITICAL:
                $this->critical($message, $context);
                break;
            case LogLevel::DEBUG:
                $this->debug($message, $context);
                break;
            case LogLevel::EMERGENCY:
                $this->emergency($message, $context);
                break;
            case LogLevel::ERROR:
                $this->error($message, $context);
                break;
            case LogLevel::INFO:
                $this->info($message, $context);
                break;
            case LogLevel::NOTICE:
                $this->notice($message, $context);
                break;
            case LogLevel::WARNING:
                $this->warning($message, $context);
                break;
            default:
                throw new InvalidArgumentException("Unrecognized log level '$level''");
        }
    }

    public static function getInstance(): self
    {
        return new self();
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Debug;

use DateTimeInterface;
use Psr\Log\InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use SimpleSAML\Module\oidc\Helpers;

class ArrayLogger implements LoggerInterface
{
    public const WEIGHT_EMERGENCY = 8;
    public const WEIGH_ALERT = 7;
    public const WEIGHT_CRITICAL = 6;
    public const WEIGHT_ERROR = 5;
    public const WEIGHT_WARNING = 4;
    public const WEIGHT_NOTICE = 3;
    public const WEIGHT_INFO = 2;
    public const WEIGHT_DEBUG = 1;

    protected int $weight;

    /** @var string[] */
    protected array $entries = [];

    public function __construct(
        protected readonly Helpers $helpers,
        int $weight = self::WEIGHT_DEBUG,
    ) {
        $this->setWeight($weight);
    }

    public function setWeight(int $weight): void
    {
        $this->weight = max(self::WEIGHT_DEBUG, min($weight, self::WEIGHT_EMERGENCY));
    }

    /**
     * @inheritDoc
     */
    public function emergency(\Stringable|string $message, array $context = []): void
    {
        // Always log emergency.
        $this->entries[] = $this->prepareEntry(LogLevel::EMERGENCY, $message, $context);
    }

    /**
     * @inheritDoc
     */
    public function alert(\Stringable|string $message, array $context = []): void
    {
        if ($this->weight > self::WEIGH_ALERT) {
            return;
        }
        $this->entries[] = $this->prepareEntry(LogLevel::ALERT, $message, $context);
    }

    /**
     * @inheritDoc
     */
    public function critical(\Stringable|string $message, array $context = []): void
    {
        if ($this->weight > self::WEIGHT_CRITICAL) {
            return;
        }
        $this->entries[] = $this->prepareEntry(LogLevel::CRITICAL, $message, $context);
    }

    /**
     * @inheritDoc
     */
    public function error(\Stringable|string $message, array $context = []): void
    {
        if ($this->weight > self::WEIGHT_ERROR) {
            return;
        }
        $this->entries[] = $this->prepareEntry(LogLevel::ERROR, $message, $context);
    }

    /**
     * @inheritDoc
     */
    public function warning(\Stringable|string $message, array $context = []): void
    {
        if ($this->weight > self::WEIGHT_WARNING) {
            return;
        }
        $this->entries[] = $this->prepareEntry(LogLevel::WARNING, $message, $context);
    }

    /**
     * @inheritDoc
     */
    public function notice(\Stringable|string $message, array $context = []): void
    {
        if ($this->weight > self::WEIGHT_NOTICE) {
            return;
        }
        $this->entries[] = $this->prepareEntry(LogLevel::NOTICE, $message, $context);
    }

    /**
     * @inheritDoc
     */
    public function info(\Stringable|string $message, array $context = []): void
    {
        if ($this->weight > self::WEIGHT_INFO) {
            return;
        }
        $this->entries[] = $this->prepareEntry(LogLevel::INFO, $message, $context);
    }

    /**
     * @inheritDoc
     */
    public function debug(\Stringable|string $message, array $context = []): void
    {
        if ($this->weight > self::WEIGHT_DEBUG) {
            return;
        }
        $this->entries[] = $this->prepareEntry(LogLevel::DEBUG, $message, $context);
    }

    /**
     * @inheritDoc
     */
    public function log($level, \Stringable|string $message, array $context = []): void
    {
        match ($level) {
            LogLevel::EMERGENCY => $this->emergency($message, $context),
            LogLevel::ALERT => $this->alert($message, $context),
            LogLevel::CRITICAL => $this->critical($message, $context),
            LogLevel::ERROR => $this->error($message, $context),
            LogLevel::WARNING => $this->warning($message, $context),
            LogLevel::NOTICE => $this->notice($message, $context),
            LogLevel::INFO => $this->info($message, $context),
            LogLevel::DEBUG => $this->debug($message, $context),
            default => throw new InvalidArgumentException("Unrecognized log level '$level''"),
        };
    }

    public function getEntries(): array
    {
        return $this->entries;
    }

    protected function prepareEntry(string $logLevel, \Stringable|string $message, array $context = []): string
    {
        return sprintf(
            '%s %s %s %s',
            $this->helpers->dateTime()->getUtc()->format(DateTimeInterface::RFC3339_EXTENDED),
            strtoupper($logLevel),
            $message,
            empty($context) ? '' : 'Context: ' . var_export($context, true),
        );
    }
}

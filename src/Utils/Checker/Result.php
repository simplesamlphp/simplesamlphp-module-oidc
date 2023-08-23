<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker;

use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;

class Result implements ResultInterface
{
    /**
     * @var string
     */
    protected string $key;

    /**
     * @var mixed
     */
    protected mixed $value;

    /**
     * Result constructor.
     * @param string $key
     * @param mixed|null $value
     */
    public function __construct(string $key, mixed $value = null)
    {
        $this->key = $key;
        $this->value = $value;
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getValue(): mixed
    {
        return $this->value;
    }

    public function setValue(mixed $value): void
    {
        $this->value = $value;
    }
}

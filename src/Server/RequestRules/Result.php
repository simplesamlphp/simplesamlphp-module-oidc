<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules;

use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;

class Result implements ResultInterface
{
    /**
     * Result constructor.
     * @param mixed|null $value
     */
    public function __construct(protected string $key, protected mixed $value = null)
    {
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

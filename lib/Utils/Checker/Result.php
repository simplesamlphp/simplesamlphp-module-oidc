<?php

namespace SimpleSAML\Module\oidc\Utils\Checker;

use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;

class Result implements ResultInterface
{
    /**
     * @var string
     */
    protected $key;

    /**
     * @var mixed
     */
    protected $value;

    /**
     * Result constructor.
     * @param string $key
     * @param mixed $value
     */
    public function __construct(string $key, $value = null)
    {
        $this->key = $key;
        $this->value = $value;
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getValue()
    {
        return $this->value;
    }

    public function setValue($value): void
    {
        $this->value = $value;
    }
}

<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker\Interfaces;

interface ResultInterface
{
    /**
     * Get result key.
     * @return string
     */
    public function getKey(): string;

    /**
     * Get result value.
     * @return mixed
     */
    public function getValue(): mixed;

    /**
     * Set (new) value.
     */
    public function setValue(mixed $value): void;
}
